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
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
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
