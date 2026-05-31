package proxy

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// helperFlag is the sentinel first argument that selects the upstream
// helper-process behaviour. When os.Args[1] is this flag, TestMain runs the
// helper (in the mode given by os.Args[2]) and exits instead of running the
// test suite, so the shutdown tests can spawn this test binary (os.Args[0]) as
// a portable upstream command rather than relying on external binaries like
// sleep or cat.
const helperFlag = "-mcp-proxy-test-helper"

// TestMain runs the upstream helper process when invoked with helperFlag,
// otherwise it runs the package test suite. There must be exactly one TestMain
// per test binary; the shutdown tests reuse this entry point as their upstream
// command, selecting a mode via the argument after helperFlag.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == helperFlag {
		runHelper(os.Args[2:])
		return
	}
	os.Exit(m.Run())
}

// runHelper executes one upstream helper-process behaviour and exits. args is
// the slice after helperFlag; args[0] is the mode.
func runHelper(args []string) {
	var mode string
	if len(args) > 0 {
		mode = args[0]
	}
	switch mode {
	case "block":
		// Block until the process is killed by reading stdin that never sees
		// data or EOF (the proxy holds the child's stdin open). Never write
		// stdout. Stands in for `sleep` — the server→client pump blocks on the
		// child's stdout (no EOF) and the child stays alive, so only a kill can
		// end Run. A blocking read keeps a goroutine parked in a syscall, unlike
		// `select {}`, which the runtime would flag as a deadlock and abort.
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "copy":
		// Copy stdin→stdout until EOF, then exit cleanly. Stands in for `cat`:
		// the proxy closes the child's stdin when the client→server pump hits
		// EOF, so the copy ends and the child exits 0.
		_, _ = io.Copy(os.Stdout, os.Stdin)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

// helperCommand returns the command and args that spawn this test binary as an
// upstream helper process in the given mode ("block" or "copy").
func helperCommand(mode string) (command string, args []string) {
	return os.Args[0], []string{helperFlag, mode}
}

// TestRun_ContextCancelUnblocks asserts that cancelling ctx returns Run
// promptly even when neither STDIO pump has reached EOF: the upstream child
// stays alive (block helper) and the client→server reader never closes.
// Cancellation must kill the child and unblock Run.
func TestRun_ContextCancelUnblocks(t *testing.T) {
	// Inject the read end of a pipe as the client reader, holding the write end
	// open, so the client→server pump blocks on a read that never sees EOF.
	// Injecting via the field avoids mutating the os.Stdin global from a test
	// whose pump goroutine reads it concurrently.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() {
		// Closing the write end gives the lingering client→server pump EOF so it
		// exits. We do not close the read end: the pump may still be mid-read on
		// it after Run returned (Run bounds its wait with a drain timeout rather
		// than joining a wedged read), and closing it concurrently with that
		// read would race. The read FD is reaped at process exit.
		_ = w.Close()
	})

	// The block helper neither reads stdin nor writes stdout, so the
	// server→client pump blocks on the child's stdout (no EOF) and the child
	// stays alive — only ctx cancel can end Run.
	command, args := helperCommand("block")
	p := New(command, args, nil)
	p.clientReader = r

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- p.Run(ctx)
	}()

	// Guard against a false positive: if the child failed to start, Run returns
	// early with a startup error and the test would "pass" without exercising
	// cancellation. Require Run to still be blocked before we cancel.
	select {
	case err := <-done:
		t.Fatalf("Run returned before cancel (early/startup failure): %v", err)
	case <-time.After(100 * time.Millisecond):
		// Run is blocked in the pumps, as intended — now cancel.
	}
	cancel()

	select {
	case err := <-done:
		// Run returned promptly after cancel. Cancellation kills the live
		// upstream child, so Wait reports the kill signal — a non-nil, non-startup
		// error. A nil error would mean the child had already exited on its own
		// before cancel (so cancellation was never actually exercised), and a
		// startup error would mean Run never reached the pumps at all.
		if err == nil {
			t.Fatal("Run returned nil after cancel: child exited on its own, cancellation was not exercised")
		}
		if isStartupError(err) {
			t.Fatalf("Run returned a startup error, not the cancel path: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s after context cancel")
	}
}

// TestRun_StdinEOFEndsRun asserts the normal STDIO path is preserved: when the
// client closes its end (EOF) the client→server pump exits and Run returns
// without any context cancellation, exactly as before context threading was
// added.
func TestRun_StdinEOFEndsRun(t *testing.T) {
	// A pipe whose write end is held open models a live client session; closing
	// it later delivers EOF on the read end. ctx is never cancelled, so Run must
	// return on EOF alone.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	// The copy helper keeps its stdout open until its stdin closes; the proxy
	// closes the child's stdin when the client→server pump hits EOF, so the
	// helper unblocks. The client→server pump exiting on EOF is what ends Run —
	// the clean STDIO-session-close path, distinct from a startup failure.
	command, args := helperCommand("copy")
	p := New(command, args, nil)
	p.clientReader = r

	done := make(chan error, 1)
	go func() {
		done <- p.Run(context.Background())
	}()

	// Guard against a false positive: confirm Run is live (the child started and
	// the pumps are running) before we deliver EOF. An early startup failure
	// would surface here instead of masquerading as a clean EOF return.
	select {
	case err := <-done:
		t.Fatalf("Run returned before EOF (early/startup failure): %v", err)
	case <-time.After(100 * time.Millisecond):
		// Run is live — deliver EOF by closing the client's write end.
	}
	_ = w.Close()

	select {
	case err := <-done:
		// Run returned on EOF without any cancellation. After the first pump
		// exits, Run kills the upstream child, so the child Wait reports
		// "signal: killed" — not nil. The honest distinction from a false pass
		// is that this happened only after EOF (the guard above proved Run was
		// live) and the error is the expected child-kill, not a startup error.
		if err != nil && isStartupError(err) {
			t.Fatalf("Run returned a startup error on the EOF path: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s on stdin EOF")
	}
}

// isStartupError reports whether err is one of Run's pre-pump startup failures
// (pipe creation or child Start). These would surface as an early return rather
// than the EOF/cancel shutdown paths the shutdown tests mean to exercise.
func isStartupError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "stdin pipe:") ||
		strings.HasPrefix(msg, "stdout pipe:") ||
		strings.HasPrefix(msg, "start server:")
}
