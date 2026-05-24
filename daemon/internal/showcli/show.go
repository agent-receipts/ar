// Package showcli implements the `agent-receipts show <seq>` subcommand:
// inspect a single receipt by its chain sequence number, read from a
// daemon-written SQLite store. It opens the database read-only so it is safe
// to run while the daemon is the active writer.
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with arbitrary args / captured I/O without shelling
// out to a built binary.
package showcli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"syscall"
	"text/tabwriter"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// Exit codes are part of the CLI contract — scripts pivot on them.
const (
	ExitOK         = 0 // receipt found and printed
	ExitNotFound   = 1 // no receipt at the requested sequence
	ExitUsageError = 2 // bad flags / unreadable DB / ambiguous chain
)

// Run executes the show subcommand with the given args (sans the program name
// and "show" subcommand token), writing output to stdout and diagnostics to
// stderr. Returns one of the Exit* constants.
//
// envLookup is split out so tests can inject a deterministic environment
// without touching the real process env. Pass os.Getenv for the production
// caller.
func Run(args []string, stdout, stderr io.Writer, envLookup func(string) string) int {
	if envLookup == nil {
		envLookup = os.Getenv
	}
	envOr := func(key, fallback string) string {
		if v := envLookup(key); v != "" {
			return v
		}
		return fallback
	}

	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: agent-receipts show <seq> [flags]")
		fmt.Fprintln(stderr, "\nPrint the full fields of the receipt at chain sequence <seq>.")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	dbPath := fs.String("db", envOr("AGENTRECEIPTS_DB", daemon.DefaultDBPath()), "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	// Empty default means "auto-detect": use the sole chain when there is
	// exactly one, otherwise require the operator to disambiguate.
	chainID := fs.String("chain-id", envLookup("AGENTRECEIPTS_CHAIN_ID"), "Chain id to read from (env: AGENTRECEIPTS_CHAIN_ID); required only when the store holds more than one chain")
	asJSON := fs.Bool("json", false, "Output the raw receipt JSON instead of human-readable text")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsageError
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "agent-receipts show: missing <seq> argument (the chain sequence number, 1-indexed)")
		return ExitUsageError
	}
	if len(rest) > 1 {
		fmt.Fprintf(stderr, "agent-receipts show: unexpected positional argument(s): %v (only one <seq> is accepted)\n", rest[1:])
		return ExitUsageError
	}
	seq, err := strconv.Atoi(rest[0])
	if err != nil || seq < 1 {
		fmt.Fprintf(stderr, "agent-receipts show: <seq> must be a positive integer, got %q\n", rest[0])
		return ExitUsageError
	}

	if *dbPath == "" {
		fmt.Fprintln(stderr, "agent-receipts show: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}

	s, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts show: open store: %v\n", err)
		return ExitUsageError
	}
	defer s.Close()

	resolved, code := resolveChainID(s, *chainID, stderr)
	if code != ExitOK {
		return code
	}

	chain, err := s.GetChain(resolved)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts show: read chain %q: %v\n", resolved, err)
		return ExitUsageError
	}
	for i := range chain {
		if chain[i].CredentialSubject.Chain.Sequence == seq {
			if *asJSON {
				return writeJSON(stdout, stderr, &chain[i])
			}
			return writeHuman(stdout, &chain[i])
		}
	}

	fmt.Fprintf(stderr, "agent-receipts show: no receipt at sequence %d in chain %q\n", seq, resolved)
	return ExitNotFound
}

// resolveChainID returns the chain id to read from. When requested is non-empty
// it is used verbatim. When empty, the store is scanned for distinct chain ids:
// exactly one is used silently, zero or more than one is a usage error with a
// helpful message. The returned int is ExitOK on success.
func resolveChainID(s *store.Store, requested string, stderr io.Writer) (string, int) {
	if requested != "" {
		return requested, ExitOK
	}

	chains, err := distinctChains(s)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts show: enumerate chains: %v\n", err)
		return "", ExitUsageError
	}
	switch len(chains) {
	case 0:
		fmt.Fprintln(stderr, "agent-receipts show: store holds no receipts")
		return "", ExitNotFound
	case 1:
		return chains[0], ExitOK
	default:
		fmt.Fprintf(stderr, "agent-receipts show: store holds %d chains; pass --chain-id to select one. Available chains:\n", len(chains))
		for _, c := range chains {
			fmt.Fprintf(stderr, "  %s\n", c)
		}
		return "", ExitUsageError
	}
}

// distinctChains returns the sorted set of chain ids present in the store.
func distinctChains(s *store.Store) ([]string, error) {
	receipts, err := s.QueryReceipts(store.Query{})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, r := range receipts {
		seen[r.CredentialSubject.Chain.ChainID] = struct{}{}
	}
	chains := make([]string, 0, len(seen))
	for c := range seen {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	return chains, nil
}

func writeJSON(stdout, stderr io.Writer, r *receipt.AgentReceipt) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintf(stderr, "agent-receipts show: encode JSON: %v\n", err)
		return ExitUsageError
	}
	return ExitOK
}

func writeHuman(stdout io.Writer, r *receipt.AgentReceipt) int {
	subj := r.CredentialSubject
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)

	row := func(label, value string) {
		if value != "" {
			fmt.Fprintf(w, "%s\t%s\n", label, value)
		}
	}

	row("Receipt ID:", r.ID)
	row("Chain:", subj.Chain.ChainID)
	fmt.Fprintf(w, "Sequence:\t%d\n", subj.Chain.Sequence)
	if subj.Chain.PreviousReceiptHash != nil {
		row("Previous hash:", *subj.Chain.PreviousReceiptHash)
	}
	if subj.Chain.Terminal != nil && *subj.Chain.Terminal {
		terminal := "true"
		if subj.Chain.Status != "" {
			terminal += " (" + string(subj.Chain.Status) + ")"
		}
		row("Terminal:", terminal)
	}
	row("Issued:", r.IssuanceDate)
	row("Issuer:", r.Issuer.ID)
	row("Principal:", subj.Principal.ID)

	row("Action type:", subj.Action.Type)
	row("Tool:", subj.Action.ToolName)
	row("Risk level:", string(subj.Action.RiskLevel))
	row("Timestamp:", subj.Action.Timestamp)
	row("Parameters hash:", subj.Action.ParametersHash)
	if t := subj.Action.Target; t != nil {
		target := t.System
		if t.Resource != "" {
			target += " " + t.Resource
		}
		row("Target:", target)
	}
	if em := subj.Action.EmitterMetadata; em != nil && em.DropCount > 0 {
		fmt.Fprintf(w, "Dropped count:\t%d\n", em.DropCount)
	}

	row("Outcome:", string(subj.Outcome.Status))
	row("Error:", subj.Outcome.Error)
	row("Response hash:", subj.Outcome.ResponseHash)

	row("Signature:", r.Proof.ProofValue)
	row("Verification method:", r.Proof.VerificationMethod)

	return exitFromFlush(w)
}

// exitFromFlush maps a tabwriter flush result to an exit code. A broken pipe
// (e.g. `agent-receipts show ... | head`) is normal CLI behaviour, not a
// failure, so it exits 0 — matching listcli.
func exitFromFlush(w *tabwriter.Writer) int {
	if err := w.Flush(); err != nil {
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) {
			return ExitOK
		}
		return ExitUsageError
	}
	return ExitOK
}
