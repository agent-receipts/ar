package socket

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/sockettest"
)

func TestListen_RefusesNonSocketPreexistingFile(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	// Create a regular file at the socket path. A misconfigured
	// AGENTRECEIPTS_SOCKET pointing here must not silently delete it.
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		ln.Close()
		t.Fatal("expected Listen to refuse a non-socket pre-existing file")
	}
	if !strings.Contains(err.Error(), "non-socket") {
		t.Errorf("error message %q should mention non-socket", err.Error())
	}

	// File must still be there — refusing implies not deleting.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Listen deleted the pre-existing file: %v", err)
	}
}

func TestListen_RefusesWhenAnotherDaemonIsLive(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	first, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = first.Serve(ctx) }()

	// Poll until a probe connect succeeds, instead of sleeping a fixed amount
	// (which is flaky on slow CI runners). 2s is generous; in practice the
	// listener is ready in microseconds on a quiet machine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, derr := net.DialTimeout("unix", path, 100*time.Millisecond); derr == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first listener did not become acceptable within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	second, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err == nil {
		second.Close()
		t.Fatal("expected Listen to refuse when another daemon is live on the same socket")
	}
	if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("error %q should mention an active daemon", err.Error())
	}
}

func TestListenerPath(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if ln.Path() != path {
		t.Errorf("Path() = %q, want %q", ln.Path(), path)
	}
}

func TestListenerCloseIdempotent(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	ln, err := Listen(Options{
		Path:    path,
		Handler: func(_ context.Context, _ Frame) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	err1 := ln.Close()
	err2 := ln.Close()

	if err1 != nil {
		t.Errorf("first Close returned error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("second Close returned error: %v", err2)
	}
}

func TestWriteFrameEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, []byte{})
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty, got: %v", err)
	}
}

func TestWriteFrameOversized(t *testing.T) {
	var buf bytes.Buffer
	oversized := make([]byte, MaxFrameSize+1)
	err := WriteFrame(&buf, oversized)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error should mention too large, got: %v", err)
	}
}

func TestWriteAndReadFrame(t *testing.T) {
	var buf bytes.Buffer

	// Write a frame
	payload := []byte(`{"test":"data"}`)
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Read it back
	data, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}

	if string(data) != string(payload) {
		t.Errorf("payload mismatch: got %q, want %q", string(data), string(payload))
	}
}

func TestReadFrameZeroLength(t *testing.T) {
	// Write a zero-length header
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0})

	_, err := readFrame(&buf)
	if err == nil {
		t.Fatal("expected error for zero-length frame")
	}
	if !strings.Contains(err.Error(), "zero-length") {
		t.Errorf("error should mention zero-length, got: %v", err)
	}
}

func TestReadFrameOversized(t *testing.T) {
	var buf bytes.Buffer
	// Write header claiming MaxFrameSize + 1 bytes
	size := MaxFrameSize + 1
	buf.WriteByte(byte(size >> 24))
	buf.WriteByte(byte(size >> 16))
	buf.WriteByte(byte(size >> 8))
	buf.WriteByte(byte(size))

	_, err := readFrame(&buf)
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error should mention too large, got: %v", err)
	}
}

func TestListenerServesMultipleFrames(t *testing.T) {
	dir := sockettest.ShortSocketDir(t)
	path := filepath.Join(dir, "events.sock")

	var frames []string
	var mu sync.Mutex

	ln, err := Listen(Options{
		Path: path,
		Handler: func(_ context.Context, f Frame) error {
			mu.Lock()
			frames = append(frames, string(f.Payload))
			mu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Start serving
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ln.Serve(ctx)
	}()

	// Give listener time to start
	time.Sleep(100 * time.Millisecond)

	// Dial and send frames
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send 3 frames
	for i := 0; i < 3; i++ {
		if err := WriteFrame(conn, []byte(fmt.Sprintf(`{"frame":%d}`, i))); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
	}

	// Wait for handler to process them
	deadline := time.Now().Add(2 * time.Second)
	for len(frames) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if len(frames) != 3 {
		t.Errorf("expected 3 frames, got %d", len(frames))
	}
}
