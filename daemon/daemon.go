// Package daemon assembles the agent-receipts-daemon's components — chain
// state, key source, receipt store, frame socket — into a single Run
// entrypoint. cmd/agent-receipts-daemon/main.go wraps Run with flag/env
// parsing and signal handling.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/agent-receipts/ar/daemon/internal/chain"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
	"github.com/agent-receipts/ar/daemon/internal/pipeline"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// Config is the daemon's startup configuration. Resolve from flags/env in
// cmd/agent-receipts-daemon/main.go and pass to Run.
type Config struct {
	// SocketPath is the Unix-domain socket the daemon listens on.
	SocketPath string

	// DBPath is the SQLite receipt-store path.
	DBPath string

	// KeyPath is the PEM-encoded Ed25519 private key path. Mode must be 0600.
	KeyPath string

	// ChainID is the chain id all incoming frames are written under. Phase 1
	// supports one chain per daemon process.
	ChainID string

	// IssuerID is embedded in receipts as issuer.id, e.g.
	// "did:agent-receipts-daemon:<host>".
	IssuerID string

	// VerificationMethodID goes into proof.verificationMethod.
	VerificationMethodID string

	// Logger receives daemon log lines. Defaults to log.Default().
	Logger *log.Logger
}

// DefaultSocketPath returns the per-OS default socket path for unprivileged
// installs. Phase 1 resolves Q1 of issue #236: macOS uses $TMPDIR, Linux uses
// $XDG_RUNTIME_DIR with a fallback. System installs override this via
// AGENTRECEIPTS_SOCKET (typically /run/agentreceipts/events.sock).
func DefaultSocketPath() string {
	switch runtime.GOOS {
	case "darwin":
		base := os.Getenv("TMPDIR")
		if base == "" {
			base = "/tmp"
		}
		return filepath.Join(base, "agentreceipts", "events.sock")
	case "linux":
		if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" {
			return filepath.Join(base, "agentreceipts", "events.sock")
		}
		return "/run/agentreceipts/events.sock"
	default:
		return ""
	}
}

// DefaultDBPath returns the per-user SQLite path used when AGENTRECEIPTS_DB
// is not set.
func DefaultDBPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".agent-receipts", "receipts.db")
	}
	return ""
}

// DefaultKeyPath returns the per-user signing-key path used when
// AGENTRECEIPTS_KEY is not set.
func DefaultKeyPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".agent-receipts", "signing.key")
	}
	return ""
}

// Run starts the daemon and blocks until ctx is cancelled. It returns the
// first fatal error or nil on graceful shutdown.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if err := validateConfig(&cfg); err != nil {
		return err
	}
	// Phase 1 supports Linux and macOS. The peer-cred capture stub on other
	// OSes rejects every connection, but starting at all on those platforms
	// would silently produce a daemon with no useful behaviour. Fail fast
	// instead. Windows ships in a follow-up issue per #236.
	switch runtime.GOOS {
	case "linux", "darwin":
	default:
		return fmt.Errorf("agent-receipts-daemon: unsupported platform %q (Phase 1 supports linux and darwin only)", runtime.GOOS)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Receipts may include peer attestation and operator-supplied disclosures;
	// world-readable is wrong by default. Tighten the DB and its WAL/SHM
	// siblings to owner+group readable (0640). Refuse to start if the file is
	// already wider than that — an operator-set 0600 must be respected, but
	// 0644/0664 typically means an umask leak.
	if err := tightenDBFiles(cfg.DBPath); err != nil {
		return err
	}

	ks := keysource.NewFile(cfg.KeyPath, cfg.VerificationMethodID)
	if err := ks.Init(); err != nil {
		return fmt.Errorf("init keysource: %w", err)
	}
	defer func() { _ = ks.Teardown() }()

	state, err := chain.LoadFromStore(st, cfg.ChainID)
	if err != nil {
		return err
	}
	cfg.Logger.Printf("loaded chain %s, next seq=%d", cfg.ChainID, state.NextSeq())

	pp := pipeline.New(state, ks, st, cfg.IssuerID)

	ln, err := socket.Listen(socket.Options{
		Path:     cfg.SocketPath,
		Handler:  func(ctx context.Context, f socket.Frame) error { return pp.Process(f) },
		ErrorLog: cfg.Logger.Printf,
	})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	cfg.Logger.Printf("agent-receipts-daemon listening on %s (chain=%s, db=%s)", ln.Path(), cfg.ChainID, cfg.DBPath)

	if err := ln.Serve(ctx); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	cfg.Logger.Printf("agent-receipts-daemon shutdown complete")
	return nil
}

// tightenDBFiles ensures the SQLite database and any WAL/SHM siblings are no
// looser than 0640 (owner rw, group r, world none). Run AFTER store.Open so
// the freshly-created files exist. SQLite creates DB files using the process
// umask, which on most systems means world-readable 0644 by default — left
// alone, that would persist sensitive receipt content. We chmod down to 0640
// when needed, preserve operator-set tighter modes (e.g. 0600), and fail-fast
// if for any reason the post-chmod perms are still wider than 0640 (e.g.
// chmod returns silently on a filesystem that ignores it, or a race wrote a
// looser mode after we set it).
func tightenDBFiles(dbPath string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dbPath + suffix
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Mode().Perm() > 0o640 {
			if err := os.Chmod(path, 0o640); err != nil {
				return fmt.Errorf("chmod %s 0640: %w", path, err)
			}
			info, err = os.Stat(path)
			if err != nil {
				return fmt.Errorf("re-stat %s after chmod: %w", path, err)
			}
		}
		if info.Mode().Perm() > 0o640 {
			return fmt.Errorf("daemon: receipts DB %s has world-accessible perms %o after chmod attempt; refusing to start", path, info.Mode().Perm())
		}
	}
	return nil
}

func validateConfig(cfg *Config) error {
	if cfg.SocketPath == "" {
		return errors.New("Config.SocketPath is required")
	}
	if cfg.DBPath == "" {
		return errors.New("Config.DBPath is required")
	}
	if cfg.KeyPath == "" {
		return errors.New("Config.KeyPath is required")
	}
	if cfg.ChainID == "" {
		return errors.New("Config.ChainID is required")
	}
	if cfg.IssuerID == "" {
		return errors.New("Config.IssuerID is required")
	}
	if cfg.VerificationMethodID == "" {
		return errors.New("Config.VerificationMethodID is required")
	}
	return nil
}
