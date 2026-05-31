package proxy

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestRun_ContextCancelUnblocks asserts that cancelling ctx returns Run
// promptly even when neither STDIO pump has reached EOF: the upstream child
// stays alive (sleep) and the client→server reader never closes. Cancellation
// must kill the child and unblock Run.
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

	// `sleep 30` neither reads stdin nor writes stdout, so the server→client
	// pump blocks on the child's stdout (no EOF) and the child stays alive —
	// only ctx cancel can end Run.
	p := New("sleep", []string{"30"}, nil)
	p.clientReader = r

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- p.Run(ctx)
	}()

	// Let the pumps reach their blocking reads before cancelling.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Run returned promptly after cancel — success. The error is the
		// expected "signal: killed" from killing the upstream child.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s after context cancel")
	}
}

// TestRun_StdinEOFEndsRun asserts the normal STDIO path is preserved: when the
// client closes its end (EOF) the client→server pump exits and Run returns
// without any signal, exactly as before context threading was added.
func TestRun_StdinEOFEndsRun(t *testing.T) {
	// A reader at EOF models a client that closed its end of the pipe to end the
	// session. Inject it as the client reader; ctx is never cancelled, so Run
	// must return on EOF alone.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	_ = w.Close() // immediate EOF on the read end

	// `cat` keeps its stdout open until its stdin closes; the proxy closes the
	// child's stdin when the client→server pump hits EOF, so cat then exits.
	p := New("cat", nil, nil)
	p.clientReader = r

	done := make(chan error, 1)
	go func() {
		done <- p.Run(context.Background())
	}()

	select {
	case <-done:
		// Run returned on EOF without any cancellation — normal flow intact.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s on stdin EOF")
	}
	_ = r.Close()
}
