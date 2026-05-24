package daemon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// unsafeSocketWarnInterval is how often Run re-emits the unsafe-socket-path
// warning while the daemon runs under --unsafe-socket-path. The first warning
// fires immediately at startup; subsequent ones at this cadence so the unsafe
// configuration stays visible in long-lived logs, not just at boot.
const unsafeSocketWarnInterval = 60 * time.Second

// checkSocketPath enforces the safe-socket-location policy from issue #538 on
// the resolved SocketPath (default or explicit override). It distinguishes
// three outcomes:
//
//   - safe path → (false, nil): start normally.
//   - unsafe path with unsafeAllowed → (true, nil): start, but the caller must
//     warn (see warnUnsafeSocketPath).
//   - unsafe path without unsafeAllowed → (false, err): refuse to start.
//
// A TCP address is rejected unconditionally — even with unsafeAllowed — because
// ADR-0010 § IPC transport rejects TCP loopback outright: it dissolves the
// filesystem permission model the peer-credential trust boundary depends on.
//
// "Safe" means the socket resolves to a location under one of the per-platform
// directories in allowedSocketRoots — the per-user runtime/data dirs and the
// privileged system run dirs. A socket in a shared, world-traversable,
// periodically-swept directory (e.g. /tmp) keeps peer-cred capture working but
// loses location privacy and may vanish under load, silently abandoning the
// safe default ADR-0010 specifies.
func checkSocketPath(socketPath string, unsafeAllowed bool) (unsafe bool, err error) {
	if looksLikeTCPAddress(socketPath) {
		return false, fmt.Errorf(
			"daemon: socket address %q is a TCP address; the daemon speaks Unix-domain sockets only and TCP loopback is rejected unconditionally (ADR-0010 § IPC transport). --unsafe-socket-path does not override this",
			socketPath,
		)
	}
	if isSocketPathSafe(socketPath) {
		return false, nil
	}
	if unsafeAllowed {
		return true, nil
	}
	return false, fmt.Errorf(
		"daemon: socket path %q is outside the per-platform safe set [%s]; refusing to start. A socket in a shared, world-traversable, swept directory (e.g. /tmp) loses the per-user trust boundary. Move it under one of the safe directories, or pass --unsafe-socket-path to override deliberately (issue #538)",
		socketPath, strings.Join(allowedSocketRoots(), ", "),
	)
}

// allowedSocketRoots returns the directories an explicit socket override may
// live under without --unsafe-socket-path, for the current platform. The
// per-platform default socket path (see DefaultSocketPath) always resolves
// under one of these, so defaults are never rejected:
//
//   - Linux: $XDG_RUNTIME_DIR (per-user, when set), /run and /var/run
//     (privileged system installs).
//   - macOS: $TMPDIR (per-user, when set), /var/run (system installs), and
//     $XDG_DATA_HOME/agent-receipts (where the per-user default socket lives
//     since issue #545 — the daemon's own private state directory, co-located
//     with receipts.db and the signing key).
//
// Relative or empty env values are ignored: a non-absolute root cannot anchor
// a containment check and per the XDG spec is invalid anyway. On Linux an unset
// $XDG_RUNTIME_DIR means "no per-user runtime dir available" — overrides then
// require --unsafe-socket-path unless they land under /run or /var/run (issue
// #538 ambiguity guidance: do not synthesize a fallback).
func allowedSocketRoots() []string {
	switch runtime.GOOS {
	case "linux":
		roots := []string{"/run", "/var/run"}
		if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" && filepath.IsAbs(x) {
			roots = append(roots, x)
		}
		return roots
	case "darwin":
		roots := []string{"/var/run"}
		if t := os.Getenv("TMPDIR"); t != "" && filepath.IsAbs(t) {
			roots = append(roots, t)
		}
		if dh := xdgDataHome(); dh != "" {
			roots = append(roots, filepath.Join(dh, "agent-receipts"))
		}
		return roots
	default:
		return nil
	}
}

// isSocketPathSafe reports whether socketPath canonicalizes to a location under
// one of allowedSocketRoots. Both the candidate and each root are canonicalized
// with EvalSymlinks before comparison so a symlink pointing out of the safe set
// (e.g. $XDG_RUNTIME_DIR/agentreceipts → /tmp/x) is judged by its real target,
// and so a root that is itself a symlink (e.g. /var/run → /run on Linux) still
// matches a socket placed via the other name.
//
// Fails closed: if the candidate path cannot be canonicalized (a non-ENOENT
// EvalSymlinks error such as EACCES on a component, or a symlink loop), it is
// treated as unsafe. Otherwise an unresolvable component could mask a symlink
// escaping the safe set. A root that cannot be canonicalized is skipped rather
// than matched.
func isSocketPathSafe(socketPath string) bool {
	canon, err := canonicalizePath(socketPath)
	if err != nil {
		return false
	}
	for _, root := range allowedSocketRoots() {
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		canonRoot, err := canonicalizePath(root)
		if err != nil {
			continue
		}
		if pathWithin(canon, canonRoot) {
			return true
		}
	}
	return false
}

// canonicalizePath resolves path to an absolute, symlink-free form. The socket
// file itself does not exist at validation time (the listener creates it), and
// its parent dir may not exist yet either, so EvalSymlinks cannot run on the
// full path. We resolve the longest existing ancestor and re-append the
// not-yet-created tail (which cannot itself be a symlink, since it does not
// exist).
//
// A non-ENOENT EvalSymlinks error — EACCES on a directory we cannot traverse,
// or ELOOP from a symlink cycle — is returned to the caller, which fails closed
// (treats the path as unsafe). We deliberately do not fall back to the literal
// unresolved path: doing so would let an unresolvable component hide a symlink
// pointing out of the safe set, contradicting "reject invalid inputs at trust
// boundaries, do not silently degrade".
func canonicalizePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	remainder := ""
	cur := abs
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			if remainder == "" {
				return resolved, nil
			}
			return filepath.Join(resolved, remainder), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("canonicalize %q: %w", path, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Walked to the filesystem root without resolving any existing
			// ancestor (only reachable if even "/" is reported missing, which
			// does not happen in practice). abs has no resolvable symlink
			// component in this case, so it is safe to return as-is.
			return abs, nil
		}
		remainder = filepath.Join(filepath.Base(cur), remainder)
		cur = parent
	}
}

// pathWithin reports whether target is root itself or a descendant of root.
// Both arguments must already be absolute and cleaned (canonicalizePath output).
func pathWithin(target, root string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// looksLikeTCPAddress reports whether s is a TCP-style socket address rather
// than a Unix-domain path. It matches an explicit tcp/tcp4/tcp6 URL scheme, or
// any bare host:port with a numeric port and no path separator — regardless of
// host (covers ":9000", "127.0.0.1:9000", "[::1]:9000", "localhost:9000",
// "example.com:9000"). The host is deliberately not restricted to loopback: the
// daemon never speaks TCP, so every host:port form is rejected uniformly rather
// than only loopback variants, keeping checkSocketPath's "TCP rejected
// unconditionally" contract honest.
//
// A Unix path containing a path separator short-circuits before the host:port
// branch. The only Unix path that could reach that branch is a bare relative
// filename, with no separator, that happens to be host:port-shaped with a
// numeric port (e.g. "foo:9000"). That is not a real daemon socket
// configuration — sockets are configured as absolute paths — so treating such
// a value as TCP is acceptable rather than a misflag of a legitimate config.
// (validateConfig does not enforce absoluteness; this is a statement about how
// the daemon is configured in practice, not an invariant.)
func looksLikeTCPAddress(s string) bool {
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "tcp://") || strings.HasPrefix(lower, "tcp4://") || strings.HasPrefix(lower, "tcp6://") {
		return true
	}
	if strings.ContainsRune(s, '/') {
		return false
	}
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	_, err = strconv.Atoi(port)
	return err == nil
}

// warnUnsafeSocketPath emits the startup warning naming an unsafe socket path,
// then re-emits it every interval until ctx is cancelled. interval <= 0 emits
// the startup line only (used by tests; production passes
// unsafeSocketWarnInterval). Run launches this in its own goroutine; log.Logger
// is safe for concurrent use, so it can share cfg.Logger with the main path.
func warnUnsafeSocketPath(ctx context.Context, logger *log.Logger, socketPath string, interval time.Duration) {
	logger.Printf(
		"level=warn unsafe socket path %q is outside the per-platform safe set; the daemon started only because --unsafe-socket-path was passed. Shared, world-traversable, periodically-swept directories (e.g. /tmp) defeat the per-user trust boundary (issue #538)",
		socketPath,
	)
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			logger.Printf("level=warn daemon still running on unsafe socket path %q (--unsafe-socket-path)", socketPath)
		}
	}
}
