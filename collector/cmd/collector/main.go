// Command collector runs the agent-receipts reference HTTP collector.
//
// The collector accepts signed receipts at POST /receipts and persists them to
// a SQLite-backed store. It performs no signing, no chain construction, no
// signature verification, and no semantic validation — its contract is the
// dumb append-only sink described in ADR-0020.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/agent-receipts/ar/collector"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z". Falls
// back to the module version from Go's build info (set automatically for
// binaries installed with `go install`), then to "dev". Mirrors the
// resolveVersion pattern used in daemon/cmd/agent-receipts-daemon/main.go.
var version string

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	addr := flag.String("addr", envOrDefault("AGENTRECEIPTS_COLLECTOR_ADDR", ":8787"), "HTTP listen address")
	dbPath := flag.String("db", envOrDefault("AGENTRECEIPTS_COLLECTOR_DB", "collector.db"), "SQLite database path (use ':memory:' for ephemeral storage — not durable)")
	maxBody := flag.Int64("max-body-bytes", envInt64OrDefault("AGENTRECEIPTS_COLLECTOR_MAX_BODY_BYTES", collector.DefaultMaxBodyBytes), "Maximum request body size in bytes")
	drainTimeout := flag.Duration("drain-timeout", envDurationOrDefault("AGENTRECEIPTS_COLLECTOR_DRAIN_TIMEOUT", 10*time.Second), "Graceful shutdown timeout")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(resolveVersion())
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("collector starting", "version", resolveVersion(), "addr", *addr, "db", *dbPath)

	store, err := collector.OpenSQLiteStore(*dbPath)
	if err != nil {
		logger.Error("failed to open store", "err", err.Error())
		os.Exit(1)
	}
	defer store.Close()

	srv, err := collector.NewServer(collector.Config{
		Addr:         *addr,
		MaxBodyBytes: *maxBody,
		Logger:       logger,
	}, store)
	if err != nil {
		logger.Error("failed to construct server", "err", err.Error())
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := collector.Run(ctx, srv, *drainTimeout, logger); err != nil {
		logger.Error("collector exited with error", "err", err.Error())
		os.Exit(1)
	}
	logger.Info("collector stopped cleanly")
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt64OrDefault(name string, def int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	var parsed int64
	if _, err := fmt.Sscanf(v, "%d", &parsed); err != nil {
		return def
	}
	return parsed
}

func envDurationOrDefault(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
