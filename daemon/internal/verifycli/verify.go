// Package verifycli implements the `agent-receipts verify` subcommand:
// validate a stored chain's signatures and hash links using a daemon-written
// SQLite store and the daemon-published public key. For a chain that has
// survived an offline key rotation the published key is the post-rotation key,
// so verification resolves the genesis key — the key that signed the first
// receipt — from the archives `agent-receipts rotate` leaves beside it, then
// traverses each key_rotated receipt forward (spec §7.3.7). It opens the
// database read-only (sdk/go/store.OpenReadOnly) so it is safe to run while the
// daemon is the active writer, and it does not require the daemon socket to be
// reachable — independent verifiability is not gated on daemon availability
// (issue #236, Section 4).
//
// Logic lives here, away from cmd/agent-receipts/main.go, so tests can drive
// the subcommand directly with arbitrary args / captured I/O without shelling
// out to a built binary.
package verifycli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/sdk/go/receipt"
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
	chainID := fs.String("chain-id", envOr("AGENTRECEIPTS_CHAIN_ID", time.Now().UTC().Format("2006-01-02")), "Chain id to verify (env: AGENTRECEIPTS_CHAIN_ID)")
	if err := fs.Parse(args); err != nil {
		// `-h` / `--help` is intentional, not an error — flag.ContinueOnError
		// surfaces it as flag.ErrHelp after writing the usage message. Exit 0
		// so scripts that probe `agent-receipts verify -h` don't see a failure.
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsageError
	}
	// `verify` takes no positional arguments — chain selection is via
	// --chain-id. Surface stray args as a usage error so a typo like
	// `agent-receipts verify --db /path/to.db extra` doesn't silently succeed
	// and hide a scripting mistake.
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "agent-receipts verify: unexpected positional argument(s): %v (use --chain-id for chain selection)\n", fs.Args())
		return ExitUsageError
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "agent-receipts verify: --db is required (no AGENTRECEIPTS_DB and no home directory)")
		return ExitUsageError
	}
	if *pubKeyPath == "" {
		fmt.Fprintln(stderr, "agent-receipts verify: --public-key is required (set AGENTRECEIPTS_PUBLIC_KEY directly, or AGENTRECEIPTS_KEY so its <KeyPath>.pub default can be derived; both are unset and no home directory is available)")
		return ExitUsageError
	}

	pubPEM, err := os.ReadFile(*pubKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts verify: read public key: %v\n", err)
		return ExitUsageError
	}
	// Validate the public key's PEM/SPKI shape upfront so a malformed key
	// surfaces as a usage error instead of being routed through
	// VerifyStoredChain → ExitChainBad, which would falsely suggest the chain
	// itself was tampered with.
	if err := validatePublicKeyPEM(pubPEM); err != nil {
		fmt.Fprintf(stderr, "agent-receipts verify: invalid public key at %s: %v\n", *pubKeyPath, err)
		return ExitUsageError
	}

	s, err := store.OpenReadOnly(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts verify: open store: %v\n", err)
		return ExitUsageError
	}
	defer s.Close()

	receipts, err := s.GetChain(*chainID)
	if err != nil {
		fmt.Fprintf(stderr, "agent-receipts verify: load chain: %v\n", err)
		return ExitUsageError
	}

	// Resolve the genesis key before verifying. After an offline key rotation
	// the *published* .pub holds the post-rotation key, but a chain is anchored
	// to the key that signed its first receipt: VerifyChain must start there and
	// traverse each key_rotated receipt forward (spec §7.3.7). `agent-receipts
	// rotate` archives every superseded public key beside the live one as
	// `<public-key>.rotated-<fingerprint>`, so a verify run pointed only at the
	// current .pub would otherwise report a rotated chain as BROKEN at receipt 0.
	// With no rotation the published key already is the genesis key and this is a
	// no-op.
	genesisPEM, genesisPath := resolveGenesisKey(receipts, candidate{path: *pubKeyPath, pem: string(pubPEM)}, stderr)
	if genesisPath != *pubKeyPath {
		fmt.Fprintf(stderr, "Note: chain is rotated; verifying from archived genesis key %s\n", genesisPath)
	}

	result := receipt.VerifyChain(receipts, genesisPEM)

	if result.ResponseHashNote != "" {
		fmt.Fprintf(stderr, "Note: %s\n", result.ResponseHashNote)
	}

	// Advisory: a final non-terminal receipt with outcome.status pending is a
	// tool call whose result receipt never arrived (ADR-0019 §O3, retained by
	// ADR-0020). It does NOT break the chain, so it never changes the exit
	// code — surface it as an advisory line regardless of Valid.
	if result.IncompleteToolRoundtrip {
		fmt.Fprintln(stdout, "Advisory: incomplete tool roundtrip: final tool call has no result receipt")
	}

	if result.Valid {
		noun := "receipts"
		if result.Length == 1 {
			noun = "receipt"
		}
		fmt.Fprintf(stdout, "Chain %s: VALID (%d %s)\n", *chainID, result.Length, noun)
		return ExitOK
	}
	fmt.Fprintf(stdout, "Chain %s: BROKEN at receipt %d\n", *chainID, result.BrokenAt)
	if result.Error != "" {
		// Surface the structured failure cause from VerifyChain — for hash
		// recompute / response_hash / chain-length / terminal-receipt errors
		// it carries detail the per-receipt status lines can't express.
		fmt.Fprintf(stdout, "  cause: %s\n", result.Error)
	}
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

// validatePublicKeyPEM rejects PEM bytes that don't decode to an Ed25519 SPKI
// public key. Catching key-format errors here lets the CLI surface them as
// ExitUsageError instead of routing them through VerifyStoredChain, where a
// malformed key would surface as a "BROKEN" chain — falsely implicating the
// receipts.
func validatePublicKeyPEM(pubPEM []byte) error {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return errors.New("PEM decode failed (no PUBLIC KEY block)")
	}
	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("PEM block type is %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse SPKI public key: %w", err)
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		return fmt.Errorf("public key is %T, want ed25519.PublicKey", parsed)
	}
	return nil
}

// candidate pairs a public-key file path with its PEM bytes so genesis-key
// resolution can report which file it settled on.
type candidate struct {
	path string
	pem  string
}

// resolveGenesisKey selects the public key that signed the chain's first
// receipt — the key VerifyChain must start from to traverse key rotations
// (spec §7.3.7). The published key (provided) is tried first, then every
// archived pre-rotation key written beside it by `agent-receipts rotate` as
// `<public-key>.rotated-*`. The first candidate whose key verifies receipt[0]'s
// signature is the genesis key.
//
// When the chain is empty, or no candidate verifies receipt[0] (a genuinely
// broken chain, or one rotated with archives the verifier can't see), the
// published key is returned unchanged so the failure is reported against the
// operator's expected key rather than an archive. A stray or malformed
// `.rotated-*` sibling is skipped with a note, not treated as fatal.
func resolveGenesisKey(receipts []receipt.AgentReceipt, provided candidate, stderr io.Writer) (pem, path string) {
	if len(receipts) == 0 {
		return provided.pem, provided.path
	}

	candidates := []candidate{provided}
	archives, _ := filepath.Glob(provided.path + ".rotated-*")
	for _, archivePath := range archives {
		data, err := os.ReadFile(archivePath)
		if err != nil {
			fmt.Fprintf(stderr, "Note: skipping archived key %s: %v\n", archivePath, err)
			continue
		}
		if err := validatePublicKeyPEM(data); err != nil {
			fmt.Fprintf(stderr, "Note: skipping archived key %s: %v\n", archivePath, err)
			continue
		}
		candidates = append(candidates, candidate{path: archivePath, pem: string(data)})
	}

	for _, c := range candidates {
		if ok, err := receipt.Verify(receipts[0], c.pem); ok && err == nil {
			return c.pem, c.path
		}
	}
	return provided.pem, provided.path
}
