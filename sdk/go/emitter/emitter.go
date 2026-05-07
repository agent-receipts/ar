// Package emitter is a thin fire-and-forget client for the agent-receipts
// daemon's local Unix-domain socket. Emit forwards a tool-call frame to the
// daemon, which captures peer credentials, canonicalises (RFC 8785), signs
// (Ed25519), and persists the receipt. The emitter does NO crypto, NO
// canonicalisation, and holds NO chain state — those moved to the daemon
// per ADR-0010 (daemon process separation, 2026-05-03).
//
// Concurrency: Emit is safe to call from multiple goroutines on a single
// Emitter instance. A mutex serialises the length-prefix + body write so
// concurrent calls cannot interleave bytes on the same socket connection.
// The dial step happens OUTSIDE the mutex so a slow accept (up to
// dialTimeout) cannot stall sibling Emit calls past their fire-and-forget
// budget; only the framed write itself holds the lock.
//
// Failure model: Emit MUST NOT block the agent on the daemon. When the
// socket is unreachable (daemon not started, socket file missing, broken
// connection) Emit logs a debug-level drop via the configured slog.Logger
// and returns nil within milliseconds. Per ADR-0010 §"Permissions and
// trust", a drop with the daemon NOT running is silent by design — there
// is no daemon to record the gap. The EAGAIN-driven local drop counter
// described in the same section ships in a follow-up commit; for now,
// every drop reason takes the same silent path.
package emitter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MaxFrameSize must agree with the daemon's socket.MaxFrameSize (1 MiB).
// Bodies larger than this are rejected at Emit; the daemon would refuse
// them at read time anyway.
const MaxFrameSize = 1 << 20

// SupportedFrameVersion mirrors the daemon's pipeline.SupportedFrameVersion.
// The wire format is versioned; bumping it requires a daemon-side
// translator, so a single supported value is the only safe contract.
const SupportedFrameVersion = "1"

// dialTimeout caps how long Emit blocks attempting to reach the daemon.
// 25ms is well under the fire-and-forget budget but still tolerant of
// slow filesystems on contended hosts; net.DialTimeout on AF_UNIX
// typically returns in microseconds when the socket is present.
const dialTimeout = 25 * time.Millisecond

// writeTimeout caps how long a single frame write can block. Local
// AF_UNIX writes of <1 MiB normally complete in microseconds; this
// deadline exists to enforce the fire-and-forget contract if a
// pathological case (full kernel send buffer, frozen daemon) appears.
const writeTimeout = 100 * time.Millisecond

// Tool identifies the tool the agent invoked. Server is optional — SDK
// channels often have no server qualifier — and produces an action.type
// of "channel.name" rather than "channel.server.name".
type Tool struct {
	Server string
	Name   string
}

// Event is one tool invocation forwarded to the daemon. Input and Output
// are raw JSON bytes; the daemon canonicalises them (RFC 8785) and writes
// only the SHA-256 digest to the receipt. Either may be nil to indicate
// no payload.
type Event struct {
	Channel  string
	Tool     Tool
	Input    json.RawMessage
	Output   json.RawMessage
	Error    string
	Decision string
}

// Option configures an Emitter at construction.
type Option func(*config)

type config struct {
	socketPath string
	sessionID  string
	logger     *slog.Logger
}

// WithSocketPath overrides the daemon socket path. When unset, the path
// is resolved from the AGENTRECEIPTS_SOCKET environment variable, then
// the per-OS default (see DefaultSocketPath).
func WithSocketPath(path string) Option {
	return func(c *config) { c.socketPath = path }
}

// WithSessionID forwards a host- or parent-process-supplied session
// identifier instead of generating a fresh UUID v4. Per ADR-0010 OQ4
// (amendment 2026-05-06), the host's session id is preferred when
// available so a single agent loop produces one logical session across
// every emitter inside it. An empty string is treated as "no host id
// provided" and New falls back to a generated UUID, since the daemon
// rejects frames with an empty session_id.
func WithSessionID(id string) Option {
	return func(c *config) { c.sessionID = id }
}

// WithLogger sets the slog.Logger used for drop diagnostics. Defaults to
// slog.Default(). Pass slog.New(slog.NewTextHandler(io.Discard, nil)) to
// silence drop logs entirely (e.g. in tests).
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// Emitter is the daemon-socket client. Construct with New, fire events
// with Emit, release the socket with Close. Safe for concurrent Emit.
type Emitter struct {
	socketPath string
	sessionID  string
	logger     *slog.Logger

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

// New returns an Emitter with the given options applied. The session_id
// is fixed for the lifetime of the returned Emitter (ADR-0010 OQ4):
// every Emit, including those after a daemon reconnect, carries the
// same value. Call Close to release the socket.
//
// New does NOT dial the daemon — dialing is lazy on the first Emit so
// that constructing an emitter cannot fail because the daemon happens
// to be down at the moment.
func New(opts ...Option) (*Emitter, error) {
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.socketPath == "" {
		cfg.socketPath = DefaultSocketPath()
	}
	if cfg.socketPath == "" {
		return nil, fmt.Errorf("emitter: no default socket path on %s; set AGENTRECEIPTS_SOCKET or pass WithSocketPath", runtime.GOOS)
	}
	if cfg.sessionID == "" {
		cfg.sessionID = uuid.NewString()
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	return &Emitter{
		socketPath: cfg.socketPath,
		sessionID:  cfg.sessionID,
		logger:     cfg.logger,
	}, nil
}

// SessionID returns the stable per-emitter session identifier. Useful for
// tests and for callers that want to log or correlate the value the
// daemon is recording on every receipt.
func (e *Emitter) SessionID() string { return e.sessionID }

// frame mirrors daemon/internal/pipeline.EmitterFrame field-for-field.
// Defined locally so the emitter does not import a daemon-internal
// package; the wire format is the contract, not the type definition.
type frame struct {
	Version   string          `json:"v"`
	TsEmit    string          `json:"ts_emit"`
	SessionID string          `json:"session_id"`
	Channel   string          `json:"channel"`
	Tool      frameTool       `json:"tool"`
	Input     json.RawMessage `json:"input,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
	Error     string          `json:"error,omitempty"`
	Decision  string          `json:"decision"`
}

type frameTool struct {
	Server string `json:"server,omitempty"`
	Name   string `json:"name"`
}

// Emit sends one event to the daemon. Returns nil even when the daemon
// is unreachable: dial and write failures are logged at debug level and
// the conn is reset for re-dial on the next Emit. Returns an error only
// for caller bugs (Emitter closed, oversized frame, invalid event fields,
// malformed Input/Output JSON) — situations a retry could not fix.
func (e *Emitter) Emit(ctx context.Context, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.Channel == "" {
		return errors.New("emitter: missing channel")
	}
	if ev.Tool.Name == "" {
		return errors.New("emitter: missing tool.name")
	}
	switch ev.Decision {
	case "allowed", "denied", "pending":
		// ok
	default:
		return fmt.Errorf("emitter: invalid decision %q (want allowed|denied|pending)", ev.Decision)
	}
	// json.Valid only checks lexical syntax — `1e400` parses as a token but
	// overflows float64, so the daemon's RFC 8785 canonicalisation (which
	// re-unmarshals into Go values) would reject it. Use Unmarshal here to
	// gate exactly what the daemon can canonicalise; better to fail fast at
	// the caller than to silently drop on the daemon side.
	if len(ev.Input) > 0 {
		if err := json.Unmarshal(ev.Input, new(interface{})); err != nil {
			return fmt.Errorf("emitter: Input is not valid JSON: %w", err)
		}
	}
	if len(ev.Output) > 0 {
		if err := json.Unmarshal(ev.Output, new(interface{})); err != nil {
			return fmt.Errorf("emitter: Output is not valid JSON: %w", err)
		}
	}

	body, err := json.Marshal(frame{
		Version:   SupportedFrameVersion,
		TsEmit:    time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: e.sessionID,
		Channel:   ev.Channel,
		Tool:      frameTool{Server: ev.Tool.Server, Name: ev.Tool.Name},
		Input:     ev.Input,
		Output:    ev.Output,
		Error:     ev.Error,
		Decision:  ev.Decision,
	})
	if err != nil {
		return fmt.Errorf("emitter: marshal frame: %w", err)
	}
	if len(body) > MaxFrameSize {
		// Surface oversize as a returned error rather than silent drop:
		// the daemon would reject the frame at read time too, so this
		// is a logic bug in the caller, not a transient outage.
		return fmt.Errorf("emitter: frame too large: %d bytes (max %d)", len(body), MaxFrameSize)
	}

	// Snapshot connection state under a brief lock. Holding e.mu across
	// the dial would serialise every concurrent Emit on a single dial's
	// 25ms timeout, blowing the per-call fire-and-forget budget under
	// load; instead we only lock for the snapshot, the optional install,
	// and the framed write.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("emitter: closed")
	}
	needDial := e.conn == nil
	e.mu.Unlock()

	if needDial {
		dialed, err := e.dial(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			e.logDrop(ctx, "dial", err)
			return nil
		}
		// Install with a check-and-set: if a sibling Emit dialled and
		// installed first while we were dialling, prefer the established
		// connection and discard ours. Costs one redundant dial in the
		// race window — cheaper than serialising every Emit on a single
		// dial. If the emitter was closed while we were dialling, drop
		// our conn so it does not leak past Close.
		e.mu.Lock()
		switch {
		case e.closed:
			e.mu.Unlock()
			_ = dialed.Close()
			return errors.New("emitter: closed")
		case e.conn == nil:
			e.conn = dialed
		default:
			// Loser of the dial race. Close the redundant conn after
			// releasing the mutex so we do not block sibling Emits on
			// the kernel close path.
			defer func() { _ = dialed.Close() }()
		}
		e.mu.Unlock()
	}

	// Hold e.mu across the write so concurrent Emits cannot interleave
	// length-prefix + body bytes on the same conn. The write deadline
	// caps how long the lock is held in the pathological case (frozen
	// daemon with a full kernel send buffer).
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("emitter: closed")
	}
	conn := e.conn
	if conn == nil {
		// A sibling Emit's write failed and reset e.conn between our
		// dial-install and write-lock acquisition. Re-dialing inline
		// would double the worst-case Emit latency on every outage
		// (ADR-0010 prefers next-Emit re-dial); drop and let the next
		// Emit re-establish.
		e.logDrop(ctx, "write", errors.New("connection reset by sibling Emit"))
		return nil
	}
	if err := e.writeFrame(ctx, conn, body); err != nil {
		e.logDrop(ctx, "write", err)
		// A failed write almost always means the daemon went away. Drop
		// the conn so the next Emit re-dials transparently. Per ADR-0010
		// the redial happens on the FOLLOWING Emit, not as an inline
		// retry — an inline retry would double the worst-case Emit
		// latency on every actual outage.
		_ = conn.Close()
		e.conn = nil
		return nil
	}
	return nil
}

// Close releases the underlying connection. After Close, subsequent Emit
// calls return an error. Safe to call multiple times.
func (e *Emitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.conn == nil {
		return nil
	}
	err := e.conn.Close()
	e.conn = nil
	if err != nil {
		return fmt.Errorf("emitter: close: %w", err)
	}
	return nil
}

// dial opens a new connection to the daemon socket. Runs OUTSIDE e.mu so
// concurrent Emit calls don't serialise on a single 25ms dialTimeout.
// DialContext is used (not net.DialTimeout) so a caller-supplied ctx with
// a tighter deadline cuts the dial short.
func (e *Emitter) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "unix", e.socketPath)
}

// writeFrame writes one length-prefixed frame to conn. The caller must
// hold e.mu so concurrent writes cannot interleave bytes on the same
// connection (the 4-byte header and body must reach the daemon as one
// contiguous sequence).
func (e *Emitter) writeFrame(ctx context.Context, conn net.Conn, body []byte) error {
	// The effective write deadline is min(now+writeTimeout, ctx.Deadline()).
	// Without honouring ctx here, a caller's tighter deadline could be
	// silently extended up to writeTimeout, breaking the fire-and-forget
	// budget callers expect when they pass a ctx with a deadline.
	deadline := time.Now().Add(writeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if err := writeAll(conn, hdr[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if err := writeAll(conn, body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	return nil
}

// writeAll handles the io.Writer short-write contract. Local AF_UNIX
// streams almost always complete in one Write, but a partial write
// would corrupt the length-prefix framing the daemon relies on, so the
// loop is correctness, not paranoia.
func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

func (e *Emitter) logDrop(ctx context.Context, stage string, err error) {
	e.logger.LogAttrs(ctx, slog.LevelDebug, "agent-receipts emitter dropped event",
		slog.String("stage", stage),
		slog.String("socket", e.socketPath),
		slog.String("err", err.Error()),
	)
}

// DefaultSocketPath returns the per-OS default path for the daemon socket.
// The OS rules match daemon.DefaultSocketPath; the emitter adds one layer:
// AGENTRECEIPTS_SOCKET is consulted first so a single env var redirects
// both daemon and emitter to a non-default socket. The daemon reads the
// env var in main, not in its DefaultSocketPath, so the two functions are
// not identical despite producing the same paths when the env var is unset.
//
//   - AGENTRECEIPTS_SOCKET (any platform): overrides all OS rules.
//   - macOS: $TMPDIR/agentreceipts/events.sock (TMPDIR defaults to /tmp).
//   - Linux with $XDG_RUNTIME_DIR set: $XDG_RUNTIME_DIR/agentreceipts/
//     events.sock — per-user, unprivileged.
//   - Linux fallback: /run/agentreceipts/events.sock (system-install path).
//   - Other platforms: empty string. New returns an error in that case
//     so callers must pass WithSocketPath explicitly.
func DefaultSocketPath() string {
	if p := os.Getenv("AGENTRECEIPTS_SOCKET"); p != "" {
		return p
	}
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
