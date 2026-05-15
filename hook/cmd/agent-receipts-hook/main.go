// Command agent-receipts-hook is a short-lived hook binary invoked by agent
// runtimes (Claude Code, Codex, …) on PostToolUse events. It reads a JSON
// frame from stdin, maps it to an emitter.Event, and forwards it to the
// agent-receipts-daemon over a Unix-domain socket. The binary always exits 0
// so it never blocks the agent, consistent with ADR-0010 §"Failure model".
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"

	"github.com/agent-receipts/ar/sdk/go/emitter"
)

// reader maps a raw stdin payload and an env-lookup function to an
// emitter.Event. The sessionID return value is the host-supplied session
// identifier (empty string when not present in the payload).
type reader func(stdin []byte, env func(string) string) (ev emitter.Event, sessionID string, err error)

var formats = map[string]reader{
	"claude-code": readClaudeCode,
}

// detect returns the format name inferred from environment variables. An empty
// string means no format could be auto-detected; the caller should fall back
// to the --format flag or exit silently.
func detect(env func(string) string) string {
	if env("CLAUDE_SESSION_ID") != "" {
		return "claude-code"
	}
	return ""
}

func main() {
	formatFlag := flag.String("format", "", "Force a specific input format (e.g. claude-code). Auto-detected when unset.")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Cap stdin at MaxFrameSize+overhead: the emitter rejects larger payloads
	// anyway, and a hard limit here prevents unbounded buffering in the
	// short-lived hook process when stdin is not the expected JSON frame.
	stdin, err := io.ReadAll(io.LimitReader(os.Stdin, emitter.MaxFrameSize+4096))
	if err != nil {
		// stdin unreadable — drop silently, exit 0.
		os.Exit(0)
	}

	env := os.Getenv

	format := *formatFlag
	if format == "" {
		format = detect(env)
	}
	if format == "" {
		// Unknown runtime — nothing to record.
		os.Exit(0)
	}

	read, ok := formats[format]
	if !ok {
		// Unsupported format — drop silently.
		os.Exit(0)
	}

	ev, sessionID, err := read(stdin, env)
	if err != nil {
		// Malformed or unrecognisable frame — drop silently.
		os.Exit(0)
	}

	opts := []emitter.Option{
		emitter.WithLogger(logger),
	}
	if sessionID != "" {
		opts = append(opts, emitter.WithSessionID(sessionID))
	}

	em, err := emitter.New(opts...)
	if err != nil {
		// No socket path available for this platform — drop silently.
		os.Exit(0)
	}
	defer em.Close()

	_ = em.Emit(context.Background(), ev)
	os.Exit(0)
}
