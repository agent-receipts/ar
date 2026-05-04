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

	// PublicKeyPath is where the daemon publishes the matching SPKI public
	// key in PEM form, mode 0644, on every startup. Read-side tools
	// (`agent-receipts verify`) load it without needing access to KeyPath or
	// the daemon's signing surface. Defaults to KeyPath + ".pub" when empty.
	PublicKeyPath string

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

// DefaultSocketPath returns the per-OS default socket path. Phase 1 resolves
// Q1 of issue #236:
//   - macOS: $TMPDIR/agentreceipts/events.sock — per-user, unprivileged.
//   - Linux with $XDG_RUNTIME_DIR set: $XDG_RUNTIME_DIR/agentreceipts/
//     events.sock — per-user, unprivileged.
//   - Linux fallback (no $XDG_RUNTIME_DIR): /run/agentreceipts/events.sock —
//     this is the system-install path and requires privileged directory
//     creation/write. Unprivileged users on systems without
//     $XDG_RUNTIME_DIR should set AGENTRECEIPTS_SOCKET explicitly.
//   - Other platforms: empty string (the daemon refuses to start outside
//     Linux/macOS, see Run).
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

// DefaultPublicKeyPath returns the default published public-key path: the
// same directory as keyPath with the suffix ".pub". Empty when keyPath is
// empty so cmd/main.go can surface a clearer "Config.KeyPath is required"
// error from validateConfig instead of a less-helpful PublicKeyPath one.
func DefaultPublicKeyPath(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	return keyPath + ".pub"
}

// Run starts the daemon and blocks until ctx is cancelled. It returns the
// first fatal error or nil on graceful shutdown.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	// Phase 1 supports Linux and macOS. Check this BEFORE validateConfig so an
	// unsupported-platform run gets a clear error, rather than the misleading
	// "Config.SocketPath is required" that DefaultSocketPath's empty return
	// would otherwise produce on those platforms. Windows ships in a follow-up
	// issue per #236.
	switch runtime.GOOS {
	case "linux", "darwin":
	default:
		return fmt.Errorf("agent-receipts-daemon: unsupported platform %q (Phase 1 supports linux and darwin only)", runtime.GOOS)
	}
	if err := validateConfig(&cfg); err != nil {
		return err
	}

	// Apply a restrictive process umask BEFORE opening the SQLite store so any
	// files SQLite creates (DB itself, and especially the lazily-created WAL
	// and SHM sidecars on first write) inherit owner+group-only permissions.
	// tightenDBFiles below remains as belt-and-braces for files that already
	// exist or for sidecars that get re-created later, but umask catches the
	// new-file case at the source so we don't have a window where a file is
	// briefly world-readable between create and chmod.
	applyRestrictiveUmask()

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o750); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Receipts may include peer attestation and operator-supplied disclosures;
	// world-readable is wrong by default. tightenDBFiles chmods the DB and any
	// WAL/SHM siblings down to 0640 when they're looser, preserves operator-set
	// tighter modes (e.g. 0600), and only refuses to start when the post-chmod
	// perms are still wider than 0640 — see its doc comment for details.
	if err := tightenDBFiles(cfg.DBPath); err != nil {
		return err
	}

	ks := keysource.NewFile(cfg.KeyPath, cfg.VerificationMethodID)
	if err := ks.Init(); err != nil {
		return fmt.Errorf("init keysource: %w", err)
	}
	defer func() { _ = ks.Teardown() }()

	if err := publishPublicKey(ks, cfg.PublicKeyPath); err != nil {
		return err
	}
	cfg.Logger.Printf("published public key to %s", cfg.PublicKeyPath)

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

// allowedDBPerm is the maximum permission set the daemon will allow on the
// receipt DB and its WAL/SHM siblings: 0640 (owner rw, group r, world none).
// "Looser than allowedDBPerm" means any bit set outside that mask, so we use a
// bitmask check instead of a numeric `>` comparison — modes like 0604
// (rw----r--, world-readable) are numerically less than 0640 but still leak
// receipts to other users on the host. Bitmask catches all such cases.
const allowedDBPerm os.FileMode = 0o640

// looserThanAllowed reports whether mode has any permission bit set outside
// the allowedDBPerm mask. mode is the Perm()-only portion (file-type bits
// already stripped).
func looserThanAllowed(mode os.FileMode) bool {
	return mode&^allowedDBPerm != 0
}

// tightenDBFiles ensures the SQLite database and any WAL/SHM siblings are no
// looser than 0640 (owner rw, group r, world none). Run AFTER store.Open so
// the freshly-created files exist. SQLite creates DB files using the process
// umask, which on most systems means world-readable 0644 by default — left
// alone, that would persist sensitive receipt content.
//
// Behaviour:
//   - File missing → skip (legitimate for WAL/SHM in non-WAL mode).
//   - File present but a symlink, FIFO, device, etc. → refuse. A pre-created
//     symlink at <db>-wal could otherwise redirect chmod to an unexpected
//     target, and a non-regular file would silently bypass the perm check.
//   - File present with any bit looser than 0640 → chmod down to 0640
//     (preserves operator-set tighter modes such as 0600 untouched).
//   - File present with perms still looser than 0640 after chmod (e.g.
//     filesystem silently ignored chmod, or a race rewrote a looser mode)
//     → refuse.
func tightenDBFiles(dbPath string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dbPath + suffix
		// Lstat (not Stat) so a symlink at <db>-wal etc. is observed AS a
		// symlink and refused, rather than silently followed and chmod'd at
		// some unexpected target.
		info, err := os.Lstat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("daemon: %s exists but is not a regular file (mode %s); refusing to chmod or use it as a SQLite path", path, info.Mode())
		}
		if looserThanAllowed(info.Mode().Perm()) {
			if err := os.Chmod(path, allowedDBPerm); err != nil {
				return fmt.Errorf("chmod %s %o: %w", path, allowedDBPerm, err)
			}
			info, err = os.Lstat(path)
			if err != nil {
				return fmt.Errorf("re-stat %s after chmod: %w", path, err)
			}
		}
		if looserThanAllowed(info.Mode().Perm()) {
			return fmt.Errorf("daemon: receipts DB %s has perms %o after chmod attempt (looser than %o); refusing to start", path, info.Mode().Perm(), allowedDBPerm)
		}
	}
	return nil
}

// publishPublicKey writes the keysource's PEM-encoded public key to path with
// mode 0644 so independent verifiers can load it without needing access to
// the private key path or the daemon's signing surface (this realises the
// "agent-receipts verify reads DB and public key directly via filesystem"
// acceptance criterion of issue #236).
//
// Behaviour:
//   - File missing → write the current public key with mode 0644.
//   - File present and identical to the current public key → no-op.
//   - File present and differs from the current public key → refuse. A
//     mismatch means either the private key changed (rotation, restored from
//     backup) or the published file was tampered with; silently overwriting
//     would invalidate verifiers' trust in receipts they already accepted.
//     Operator must remove the stale file deliberately.
//   - File present but a symlink, FIFO, device, etc. → refuse. A pre-created
//     symlink would otherwise let an attacker with write access to the parent
//     redirect the chmod / write to an arbitrary target.
func publishPublicKey(ks keysource.KeySource, path string) error {
	if path == "" {
		return errors.New("Config.PublicKeyPath is required")
	}
	pubPEM, err := ks.PublicKey()
	if err != nil {
		return fmt.Errorf("read public key from keysource: %w", err)
	}

	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf(
				"daemon: public-key path %s exists but is not a regular file (mode %s); refusing to overwrite",
				path, info.Mode(),
			)
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read existing public-key file %s: %w", path, err)
		}
		if string(existing) == pubPEM {
			// Already up-to-date. Re-chmod in case the file was created with
			// a stricter umask but later loosened — converging the bit set is
			// cheap and aligns with the "publish on every startup" contract.
			if info.Mode().Perm() != 0o644 {
				if err := os.Chmod(path, 0o644); err != nil {
					return fmt.Errorf("chmod %s 0644: %w", path, err)
				}
			}
			return nil
		}
		return fmt.Errorf(
			"daemon: public-key file %s differs from current keysource public key; refusing to overwrite. Remove the file deliberately if the signing key was rotated or restored from backup",
			path,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat public-key path %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create public-key dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(pubPEM), 0o644); err != nil {
		return fmt.Errorf("write public-key file %s: %w", path, err)
	}
	// WriteFile honours the process umask, which the daemon tightens to 0027
	// before this point — so a fresh write would be 0640 instead of the 0644
	// we want for a public key. Chmod afterwards to land on the intended mode
	// without reverting the umask (which would loosen WAL/SHM perms).
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("chmod %s 0644: %w", path, err)
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
	if cfg.PublicKeyPath == "" {
		cfg.PublicKeyPath = DefaultPublicKeyPath(cfg.KeyPath)
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
