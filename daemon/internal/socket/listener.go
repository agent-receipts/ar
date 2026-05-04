package socket

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// MaxFrameSize caps a single emitter frame at 1 MiB. Larger frames are
// rejected outright so a misbehaving emitter cannot exhaust the daemon's
// memory by claiming an arbitrary length prefix.
const MaxFrameSize = 1 << 20

// Frame pairs the JSON payload an emitter sent with the OS-attested peer cred
// captured at accept time. Handler receives one Frame per emitter message.
type Frame struct {
	Payload []byte
	Peer    PeerCred
}

// Handler processes a single frame. Implementations MUST be safe for concurrent
// use (the listener invokes Handler from many connection goroutines). A
// returned error is logged via the listener's ErrorLog but is otherwise
// non-fatal — the connection stays open for subsequent frames.
type Handler func(ctx context.Context, f Frame) error

// Listener wraps a net.UnixListener with peer-cred capture and length-prefix
// framing. Construct via Listen, drive via Serve, stop via Close.
type Listener struct {
	ln       *net.UnixListener
	path     string
	handler  Handler
	errorLog func(format string, args ...any)

	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once

	// Active connections, tracked so Close can break their blocking reads.
	// Without this, an idle peer connected to the daemon would block shutdown
	// forever — io.ReadFull on a *net.UnixConn does not observe ctx.Done.
	connsMu sync.Mutex
	conns   map[*net.UnixConn]struct{}
}

// Options configure a Listener.
type Options struct {
	// Path is the socket path. Required. The parent directory is created with
	// 0750 if missing. Any pre-existing socket file at Path is removed first
	// (a stale socket from a previous run is the common case).
	Path string

	// Handler is called for each received frame. Required.
	Handler Handler

	// ErrorLog logs non-fatal errors (handler errors, malformed frames). When
	// nil, errors are silently discarded.
	ErrorLog func(format string, args ...any)
}

// Listen binds a SOCK_STREAM Unix-domain listener at opts.Path and returns it
// ready to Serve. The caller must call Close to release the socket file.
func Listen(opts Options) (*Listener, error) {
	if opts.Path == "" {
		return nil, errors.New("socket: Path is required")
	}
	if opts.Handler == nil {
		return nil, errors.New("socket: Handler is required")
	}

	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o750); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	// If the path exists, it's one of three cases:
	//   1. A non-socket file/dir — refuse, never silently delete a regular
	//      file or directory pointed at by a misconfigured socket path.
	//   2. A live socket with a daemon already accepting on it — refuse,
	//      removing it would orphan that daemon's pathname (its listener
	//      keeps running, but no client can find it).
	//   3. A stale socket (file present, no listener) — safe to remove.
	if info, err := os.Lstat(opts.Path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket: refusing to remove non-socket file at %s (mode %s); pick a different AGENTRECEIPTS_SOCKET", opts.Path, info.Mode())
		}
		// Probe-connect with a short timeout. We must distinguish three
		// outcomes:
		//   nil error      → another daemon is live, refuse.
		//   ECONNREFUSED   → socket file exists but no listener — stale.
		//   anything else  → indeterminate (permission error, EAGAIN under
		//                    backlog saturation, EHOSTUNREACH on a fuse
		//                    mount, plain timeout). Removing on these would
		//                    risk orphaning a still-running daemon, so refuse
		//                    and let the operator investigate.
		c, derr := net.DialTimeout("unix", opts.Path, 100*time.Millisecond)
		if derr == nil {
			c.Close()
			return nil, fmt.Errorf("socket: another daemon is already listening on %s; stop it before starting a second instance", opts.Path)
		}
		if !errors.Is(derr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("socket: %s is held by an unreachable peer (%v); refusing to remove the socket file (would orphan a running daemon if it is still live)", opts.Path, derr)
		}
		if err := os.Remove(opts.Path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat socket path: %w", err)
	}

	addr := &net.UnixAddr{Name: opts.Path, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", opts.Path, err)
	}
	// 0660 — connecting processes need write access to the socket file. The
	// daemon's group governs who may emit; non-group members get EACCES on
	// connect. (Unprivileged single-user installs typically run with the
	// user's own group.)
	if err := os.Chmod(opts.Path, 0o660); err != nil {
		ln.Close()
		_ = os.Remove(opts.Path)
		return nil, fmt.Errorf("chmod socket: %w", err)
	}

	return &Listener{
		ln:       ln,
		path:     opts.Path,
		handler:  opts.Handler,
		errorLog: opts.ErrorLog,
		closed:   make(chan struct{}),
		conns:    make(map[*net.UnixConn]struct{}),
	}, nil
}

// trackConn registers c so Close can break its read loop, and atomically
// claims a slot on the WaitGroup. Both happen under connsMu so the closed
// check, the conns map insert, and the wg.Add together race-free against
// Close (which holds the same mutex while it observes l.closed and iterates
// conns). Without that atomicity the race detector legitimately flags
// wg.Add(1) racing wg.Wait at counter == 0.
func (l *Listener) trackConn(c *net.UnixConn) bool {
	l.connsMu.Lock()
	defer l.connsMu.Unlock()
	select {
	case <-l.closed:
		// Listener already closing; reject the new conn.
		return false
	default:
	}
	l.conns[c] = struct{}{}
	l.wg.Add(1)
	return true
}

func (l *Listener) untrackConn(c *net.UnixConn) {
	l.connsMu.Lock()
	delete(l.conns, c)
	l.connsMu.Unlock()
}

// Path returns the socket file path.
func (l *Listener) Path() string { return l.path }

// Serve accepts connections until ctx is cancelled or Close is called. Each
// accepted connection is handled in its own goroutine; Serve returns nil on
// graceful shutdown.
func (l *Listener) Serve(ctx context.Context) error {
	// Translate ctx cancellation into a listener Close so Accept returns.
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-l.closed:
		}
	}()

	for {
		conn, err := l.ln.AcceptUnix()
		if err != nil {
			select {
			case <-l.closed:
				l.wg.Wait()
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				l.wg.Wait()
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}

		// Capture peer cred BEFORE reading any frame, so a forking emitter
		// cannot mislabel itself.
		peer, err := capturePeer(conn)
		if err != nil {
			l.logf("peer-cred capture failed: %v", err)
			conn.Close()
			continue
		}

		// Track the conn so Close() can unblock its read loop on shutdown.
		// trackConn also claims the WaitGroup slot atomically with the closed
		// check; if we lost the race with Close(), drop this conn.
		if !l.trackConn(conn) {
			conn.Close()
			continue
		}
		go func() {
			defer l.wg.Done()
			defer conn.Close()
			defer l.untrackConn(conn)
			l.serveConn(ctx, conn, peer)
		}()
	}
}

// Close stops accepting new connections, closes any in-flight connections to
// unblock their read loops, removes the socket file, and waits for handlers
// to finish. Idempotent.
func (l *Listener) Close() error {
	var closeErr error
	l.once.Do(func() {
		// Hold connsMu across the whole shutdown signal so trackConn's closed
		// check, the wg.Add it does, and our snapshot of l.conns are linearised:
		// any Accept-loop goroutine that's about to register a fresh conn either
		// finishes BEFORE we enter this critical section (in which case we close
		// it explicitly below and wg.Wait will see it through) or AFTER we exit
		// (in which case its trackConn observes l.closed and rejects).
		l.connsMu.Lock()
		close(l.closed)
		closeErr = l.ln.Close()
		// net.UnixListener.Close unlinks the socket file when the listener was
		// created via ListenUnix and SetUnlinkOnClose hasn't been overridden
		// — which matches our usage. We still call os.Remove explicitly as a
		// belt-and-braces measure for cases where Close cannot remove the
		// path (the daemon was killed and never reached this code, the path
		// was replaced underneath us, etc.). The Remove is allowed to fail
		// silently.
		_ = os.Remove(l.path)

		// Break in-flight io.ReadFull calls. Without this, an idle peer
		// connected to the daemon would block shutdown indefinitely — closing
		// the listener does not propagate to already-accepted UDS conns.
		for c := range l.conns {
			_ = c.Close()
		}
		l.connsMu.Unlock()
	})
	l.wg.Wait()
	return closeErr
}

func (l *Listener) serveConn(ctx context.Context, conn *net.UnixConn, peer PeerCred) {
	for {
		// Stop reading on shutdown.
		select {
		case <-ctx.Done():
			return
		default:
		}

		payload, err := readFrame(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			// During shutdown, conn.Close() races the in-flight ReadFull and
			// surfaces as a generic "use of closed network connection" wrap;
			// treat it as a clean exit rather than a logged read-frame error.
			select {
			case <-l.closed:
				return
			default:
			}
			l.logf("read frame: %v", err)
			return
		}

		if err := l.handler(ctx, Frame{Payload: payload, Peer: peer}); err != nil {
			l.logf("handler error: %v", err)
		}
	}
}

func (l *Listener) logf(format string, args ...any) {
	if l.errorLog == nil {
		return
	}
	l.errorLog(format, args...)
}

// readFrame reads one length-prefixed frame from r. Format: 4-byte big-endian
// payload length followed by that many JSON bytes.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, fmt.Errorf("zero-length frame")
	}
	if n > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes (max %d)", n, MaxFrameSize)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return buf, nil
}

// WriteFrame writes one length-prefixed frame to w. Exposed so the daemon's
// own integration tests (which dial the listener as if they were emitters)
// don't reimplement the wire encoding. This package is daemon-internal, so
// Phase 2 emitter SDKs in other modules cannot import it directly — they
// reimplement the same encoding (4-byte big-endian length prefix, MaxFrameSize
// cap), which is documented in daemon/README.md so the wire form stays
// canonical across implementations.
//
// io.Writer's contract permits short writes with a nil error. A short write
// would corrupt framing for the receiver, so writes are looped until all
// bytes are sent or an error is returned.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("WriteFrame: empty payload")
	}
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("WriteFrame: payload too large: %d bytes (max %d)", len(payload), MaxFrameSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if err := writeAll(w, hdr[:]); err != nil {
		return fmt.Errorf("WriteFrame header: %w", err)
	}
	if err := writeAll(w, payload); err != nil {
		return fmt.Errorf("WriteFrame body: %w", err)
	}
	return nil
}

func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
