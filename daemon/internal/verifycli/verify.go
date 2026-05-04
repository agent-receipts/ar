// Package verifycli implements the `agent-receipts verify` subcommand:
// validate a stored chain's signatures and hash links using a daemon-written
// SQLite store and the daemon-published public key. It opens the database
// read-only (sdk/go/store.OpenReadOnly) so it is safe to run while the daemon
// is the active writer, and it does not require the daemon socket to be
// reachable — independent verifiability is not gated on daemon availability
// (issue #236, Section 4).
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with arbitrary args / captured I/O without shelling
// out to a built binary.
package verifycli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// Exit codes are part of the CLI contract — scripts and CI checks pivot on
// them. Keep these stable.
const (
	ExitOK         = 0 // chain verified
	ExitChainBad   = 1 // chain failed verification
	ExitUsageError = 2 // bad flags / unreadable DB or key file
)

// Run executes the verify subcommand with the given args (sans the program
// name and "verify" subcommand token), writing human-readable output to
// stdout and diagnostics to stderr. Returns one of the Exit* constants;
// cmd/agent-receipts/main.go forwards it to os.Exit.
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

	// Resolve the public-key default in two steps so the flag declaration
	// stays readable: --public-key inherits AGENTRECEIPTS_PUBLIC_KEY when set,
	// otherwise it falls back to <KeyPath>.pub computed from the same KeyPath
	// the daemon would use, so a verify run with no flags works after the
	// daemon has run at least once with the same per-user paths.
	keyPath := envOr("AGENTRECEIPTS_KEY", daemon.DefaultKeyPath())
	defaultPubKey := envOr("AGENTRECEIPTS_PUBLIC_KEY", daemon.DefaultPublicKeyPath(keyPath))

	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", envOr("AGENTRECEIPTS_DB", daemon.DefaultDBPath()), "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	pubKeyPath := fs.String("public-key", defaultPubKey, "PEM-encoded SPKI public key path (env: AGENTRECEIPTS_PUBLIC_KEY)")
	chainID := fs.String("chain-id", envOr("AGENTRECEIPTS_CHAIN_ID", "default"), "Chain id to verify (env: AGENTRECEIPTS_CHAIN_ID)")
	if err := fs.Parse(args); err != nil {
		// `-h` / `--help` is intentional, not an error — flag.ContinueOnError
		// surfaces it as flag.ErrHelp after writing the usage message. Exit 0
		// so scripts that probe `agent-receipts verify -h` don't see a failure.
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsageError
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "agent-receipts verify: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}
	if *pubKeyPath == "" {
		fmt.Fprintln(stderr, "agent-receipts verify: --public-key is required (no AGENTRECEIPTS_PUBLIC_KEY/_KEY and no home directory)")
		return ExitUsageError
	}

	pubPEM, err := os.ReadFile(*pubKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts verify: read public key: %v\n", err)
		return ExitUsageError
	}

	s, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts verify: open store: %v\n", err)
		return ExitUsageError
	}
	defer s.Close()

	result, err := s.VerifyStoredChain(*chainID, string(pubPEM))
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts verify: %v\n", err)
		return ExitUsageError
	}

	if result.ResponseHashNote != "" {
		fmt.Fprintf(stderr, "Note: %s\n", result.ResponseHashNote)
	}

	if result.Valid {
		fmt.Fprintf(stdout, "Chain %s: VALID (%d receipts)\n", *chainID, result.Length)
		return ExitOK
	}
	fmt.Fprintf(stdout, "Chain %s: BROKEN at receipt %d\n", *chainID, result.BrokenAt)
	for _, rv := range result.Receipts {
		status := "ok"
		switch {
		case !rv.SignatureValid:
			status = "BAD SIGNATURE"
		case !rv.HashLinkValid:
			status = "BAD HASH LINK"
		case !rv.SequenceValid:
			status = "BAD SEQUENCE"
		}
		fmt.Fprintf(stdout, "  [%d] %s — %s\n", rv.Index, rv.ReceiptID, status)
	}
	return ExitChainBad
}
