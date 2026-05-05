// Command agent-receipts-daemon runs the receipts daemon: a single OS-user
// process that owns the Ed25519 signing key and the SQLite receipt store, and
// receives fire-and-forget event frames from emitters over a Unix-domain
// socket. See ADR-0010 for design.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/agent-receipts/ar/daemon"
)

func main() {
	cfg := daemon.Config{
		SocketPath: envOrDefault("AGENTRECEIPTS_SOCKET", daemon.DefaultSocketPath()),
		DBPath:     envOrDefault("AGENTRECEIPTS_DB", daemon.DefaultDBPath()),
		KeyPath:    envOrDefault("AGENTRECEIPTS_KEY", daemon.DefaultKeyPath()),
		// PublicKeyPath defaults to <KeyPath>.pub. Resolve the default AFTER
		// flag.Parse so a user-supplied --key (which overrides KeyPath) is
		// what we derive against — pre-filling here against the env/default
		// KeyPath would silently ignore the operator's --key choice.
		// AGENTRECEIPTS_PUBLIC_KEY (if set) wins over the derived default.
		PublicKeyPath:        os.Getenv("AGENTRECEIPTS_PUBLIC_KEY"),
		ChainID:              envOrDefault("AGENTRECEIPTS_CHAIN_ID", "default"),
		IssuerID:             envOrDefault("AGENTRECEIPTS_ISSUER_ID", "did:agent-receipts-daemon:local"),
		VerificationMethodID: envOrDefault("AGENTRECEIPTS_VERIFICATION_METHOD", "did:agent-receipts-daemon:local#k1"),
	}

	flag.StringVar(&cfg.SocketPath, "socket", cfg.SocketPath, "Unix-domain socket path (env: AGENTRECEIPTS_SOCKET)")
	flag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite receipt-store path (env: AGENTRECEIPTS_DB)")
	flag.StringVar(&cfg.KeyPath, "key", cfg.KeyPath, "Ed25519 PEM private key path, mode 0600 (env: AGENTRECEIPTS_KEY)")
	flag.StringVar(&cfg.PublicKeyPath, "public-key", cfg.PublicKeyPath, "Path to publish the SPKI public key as PEM, mode 0644 (default: <--key>.pub) (env: AGENTRECEIPTS_PUBLIC_KEY)")
	flag.StringVar(&cfg.ChainID, "chain-id", cfg.ChainID, "Chain id to write under (env: AGENTRECEIPTS_CHAIN_ID)")
	flag.StringVar(&cfg.IssuerID, "issuer-id", cfg.IssuerID, "Receipt issuer.id (env: AGENTRECEIPTS_ISSUER_ID)")
	flag.StringVar(&cfg.VerificationMethodID, "verification-method", cfg.VerificationMethodID, "proof.verificationMethod (env: AGENTRECEIPTS_VERIFICATION_METHOD)")
	flag.Parse()

	// Apply the <--key>.pub default now that flag.Parse has finalised KeyPath.
	// daemon.validateConfig also covers this path for library callers; doing
	// it here too keeps the startup log line ("published public key to ...")
	// printing the same path the daemon writes to.
	if cfg.PublicKeyPath == "" {
		cfg.PublicKeyPath = daemon.DefaultPublicKeyPath(cfg.KeyPath)
	}

	logger := log.New(os.Stderr, "agent-receipts-daemon ", log.LstdFlags|log.Lmicroseconds)
	cfg.Logger = logger

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := daemon.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "agent-receipts-daemon: %v\n", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
