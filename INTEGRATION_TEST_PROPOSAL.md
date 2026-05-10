# Integration Test Suite Design for agent-receipts-daemon v0.8.0-alpha.2

## Executive Summary

The v0.8.0-alpha.2 daemon release introduces process-separated receipt signing and storage (ADR-0010). Manual soak testing revealed the TypeScript SDK emitter is silently broken: frames are dropped without error signal to the caller. The existing test harness in `daemon/integration_test.go` covers daemon-side logic but provides no cross-emitter validation framework. This proposal designs an integration test suite to:

1. **Unblock the soak test** by catching emitter regressions (like the ts SDK bug) automatically
2. **Validate daemon stability** under the 5-emitter load pattern (concurrent frames, daemon restarts, chain continuity)
3. **Add observability** so test failures surface root causes (dropped frames, buffering issues, signing bugs)

---

## Current State

### What Works

- **daemon/integration_test.go**: Comprehensive daemon-side coverage. Go-language tests using real Unix sockets, real SQLite, real signing keys. Tests concurrent emitters (TestConcurrentEmittersSingleChain), peer cred capture, chain resumption, verify CLI, daemon shutdown.
- **cross-sdk-tests/**: Shared receipt vectors (Go, Python, TS) for cross-language signature verification. Does NOT test daemon integration or emitter correctness.
- **Each SDK's emitter**: Go, Python, TypeScript all implement the same fire-and-forget pattern over Unix socket (25ms dial, 100ms write timeout).

### What's Missing

1. **No cross-emitter integration tests**: No tests that verify all 5 emitters (sdk/go, sdk/ts, sdk/py, mcp-proxy, openclaw) can emit frames to the daemon and have receipts land correctly.
2. **No emitter regression detection**: The ts SDK emitter is silently broken (frames drop without error), and there's no automated test to catch this before release.
3. **No daemon observability in tests**: Daemon logs nothing (intentional silence for v0.8.0-alpha.1 security model). Tests have no way to diagnose why frames drop or why the chain has gaps.
4. **No multi-daemon scenarios**: No tests for daemon restart with chain resumption or concurrent daemon instances.
5. **No emitter-daemon protocol validation**: No tests that verify frame format, length-prefix framing, or wire protocol compliance from each emitter.

---

## Architecture: Test Suite Location and Structure

### Test Directory Layout

```
daemon/tests/
├── README.md                 # Test strategy, how to run, troubleshooting
├── integration_test.go       # Top-level test suite harness (Go, uses go test)
├── framework.go              # Shared test fixtures: daemon startup, frame emission, receipt polling
├── emitters/
│   ├── go_emitter_test.go    # Go SDK emitter over daemon socket
│   ├── ts_emitter_test.go    # TypeScript SDK emitter (Node child process)
│   ├── py_emitter_test.go    # Python SDK emitter (uv subprocess)
│   └── mcp_proxy_test.go     # mcp-proxy emitter (if available as library; else skip v1)
├── scenarios/
│   ├── concurrent_test.go    # All 5 emitters fire concurrently; validate chain
│   ├── daemon_restart_test.go # Daemon stop/start; chain resumes
│   ├── protocol_test.go      # Frame format, length-prefix, timeout behavior
│   └── chain_integrity_test.go # Cross-emitter chain gaps, duplicates
└── fixtures/
    ├── emitter_helpers/
    │   ├── ts_emitter.js     # TypeScript helper: emit one frame, exit (run as subprocess)
    │   ├── py_emitter.py     # Python helper: emit one frame, exit (run as subprocess)
    │   └── go_emitter.go     # Go helper: emit one frame (can call directly or as subprocess)
    └── keys/
        └── testkey_*         # Pre-generated Ed25519 keys for tests
```

### Language Choice

**Go for test harness, polyglot helpers for emitters.**

- **Why Go for the harness:** daemon/ is already Go; no new toolchain dependency. Integration tests run as `go test -tags=integration ./tests/...` alongside the existing daemon unit tests. Tight integration with daemon/Run, socket paths, file fixtures.
- **Why polyglot helpers:** Each SDK's emitter is in its native language. Testing the TS SDK emitter requires a Node environment, Python requires uv/pytest. Spinning up subprocess helpers (like the existing `runEmitterHelper` in `daemon/integration_test.go`) is the most realistic test — it exercises the actual emitter binary, not a copy or stub. This catches bugs the Go test harness cannot (e.g., "does the TS emitter correctly handle ECONNREFUSED?").

---

## Test Scope: Key Scenarios

### Baseline Emitter Correctness (per-emitter, blocking)

1. **[Go Emitter]** Emit one frame; verify it lands in the daemon's SQLite store
2. **[TS Emitter]** Emit one frame via Node subprocess; verify receipt is stored
3. **[Python Emitter]** Emit one frame via uv subprocess; verify receipt is stored
4. **[All Emitters]** Emit with `decision=allowed|denied|pending`; verify decision is preserved
5. **[All Emitters]** Emit with `input`, `output`, `error` payloads; verify hashes match canonical form

**Rationale:** These are the "soak test blockers." Each emitter must produce at least one valid receipt before moving to concurrent scenarios. Catching the ts SDK issue here.

### Daemon Robustness Under Load

6. **[Concurrent Emitters]** All 5 emitters fire 10 frames each (50 total) concurrently; verify chain has no gaps, no duplicates, all 50 receipts land
7. **[Interleaved Frames]** Go and TS emitters alternate submitting frames; verify chain order is monotonic
8. **[Rapid Restarts]** TS emitter spins up 3 times in quick succession (short-lived processes); verify 3 receipts land with correct seq
9. **[Idle Connection]** Python emitter dials daemon, idles (connection stays open for 2s), then closes; daemon must not deadlock

### Chain Integrity Across Emitters

10. **[Cross-Emitter Chain]** Go emits, then TS emits, then Python emits; verify all 3 receipts have correct seq and prev_hash
11. **[Chain Continuity After Daemon Restart]** Emit 5 frames (any mix of emitters); shut daemon down; emit cannot land; restart daemon; emit 5 more frames; verify new frames resume seq from 5, not restart at 1

### Wire Protocol Correctness

12. **[Oversized Frame]** Emit frame >1 MiB; verify frame is rejected without corrupting the daemon or chain
13. **[Malformed JSON Input]** Emit frame with `input: "not json"`; verify daemon drops frame and logs nothing (fire-and-forget), chain unaffected
14. **[Length-Prefix Errors]** Write bad length-prefix (e.g., 0xFFFFFFFF then truncate); verify daemon closes connection gracefully, chain unaffected
15. **[Timeout Behavior]** Emit frame, then block write for 150ms (exceeding 100ms timeout); verify emitter drops with debug log, daemon unaffected

### Known-Regression Tests (Phased)

16. **[TS Emitter Drops]** *After ts SDK is fixed:* Verify ts emitter does NOT drop valid frames; add regression check that future changes preserve this
17. **[Peer Cred Capture]** Verify daemon captures correct pid/uid for each emitter type (Go differs from TS subprocess differs from Python subprocess)

---

## Test Infrastructure

### Fixtures: `framework.go`

```go
// Daemon startup helper
type DaemonFixture struct {
    Config    daemon.Config
    PublicKey string      // PEM public key
    cancel    func()      // cancellation for graceful shutdown
    // ...
}
func startDaemon(t *testing.T) (*DaemonFixture, error)

// Receipt polling helper (existing pattern from integration_test.go)
func waitForReceiptCount(t *testing.T, store *store.Store, chainID string, 
    count int, timeout time.Duration) ([]receipt.AgentReceipt, error)

// Frame emission helper
func emitFrame(t *testing.T, socketPath string, frame pipeline.EmitterFrame) error

// Subprocess emitter spawners
func runTSEmitter(t *testing.T, socketPath string, sessionID string) error
func runPyEmitter(t *testing.T, socketPath string, sessionID string) error
func runGoEmitter(t *testing.T, socketPath string, sessionID string) error
```

### Observability: Frame Tracing Log

Problem: Daemon logs nothing. When a test fails (chain has gaps or fewer receipts than expected), there's no way to know if:
- Emitter crashed
- Frame was malformed
- Daemon hung
- Database write failed
- Peer cred capture failed

**Solution: Add optional tracing to daemon Run.**

New optional `Config.TraceLog` (io.Writer, defaults to io.Discard):

```go
type Config struct {
    // ...
    TraceLog io.Writer  // nil or io.Discard = silent; test framework sets to buffer
}
```

When set, the daemon logs (at trace level, structured JSON for machine parsing):
- Frame received: `{"event":"frame_received","source":"<emitter_pid>","session_id":"...","ts":"..."}`
- Frame processed: `{"event":"frame_processed","seq":5,"receipt_id":"...","ts":"..."}`
- Frame dropped: `{"event":"frame_dropped","reason":"oversized|malformed|timeout|...","ts":"..."}`
- Error: `{"event":"error","component":"socket|pipeline|store","message":"...","ts":"..."}`

Tests that fail can inspect the trace log and see exactly where the frame went:

```go
func TestTSEmitterSingleFrame(t *testing.T) {
    fixture, _ := startDaemonWithTracing(t)
    defer fixture.Cleanup()
    
    if err := runTSEmitter(t, fixture.Config.SocketPath, "test-session"); err != nil {
        t.Logf("TS emitter error: %v", err)
    }
    
    receipts, err := waitForReceiptCount(t, fixture.Config.DBPath, fixture.Config.ChainID, 1, 5*time.Second)
    if err != nil {
        // Inspect daemon trace log
        t.Logf("Daemon trace:\n%s", fixture.TraceLog.String())
        t.Fatalf("Expected 1 receipt, got error: %v", err)
    }
}
```

**Trade-off:** Adds a small amount of logging code to the daemon (guard-gated by TraceLog != nil). Production daemon (TraceLog = nil) is unaffected. Tests get visibility without compromising security model.

---

## Implementation Plan

### Phase 1: Foundation (Unblock Soak Test)

**Deliverables:**
- [ ] `daemon/tests/framework.go` — shared fixtures (daemon startup, emitter spawners, receipt polling)
- [ ] `daemon/tests/emitters/go_emitter_test.go` — Go SDK emitter validation (single frame, concurrent)
- [ ] `daemon/tests/emitters/ts_emitter_test.go` — TS SDK emitter validation (via Node subprocess); **detects the v0.8.0-alpha.2 regression**
- [ ] `daemon/tests/emitters/py_emitter_test.go` — Python SDK emitter validation (via uv subprocess)
- [ ] `daemon/tests/scenarios/concurrent_test.go` — All 3 emitters fire concurrently; chain integrity
- [ ] `daemon/tests/fixtures/emitter_helpers/{ts_emitter.js,py_emitter.py}` — Subprocess helpers
- [ ] Optional: daemon TraceLog for test debugging (deferred if not needed for Phase 1)

**Test count:** ~8 tests
**Blockers:** None; all three SDKs have working emitters in main
**Est. lines of code:** ~600 Go, ~100 TS, ~100 Py

### Phase 2: Robustness & Protocol (Stabilize for MVP)

**Deliverables:**
- [ ] `daemon/tests/scenarios/daemon_restart_test.go` — Stop/start with chain resumption
- [ ] `daemon/tests/scenarios/protocol_test.go` — Oversized frames, malformed JSON, timeout behavior
- [ ] Daemon TraceLog implementation (if not done in Phase 1)
- [ ] Chain integrity validation helpers (detect gaps, duplicates, broken links)

**Test count:** ~6 tests
**Est. lines of code:** ~400 Go

### Phase 3: Regression Suite & Packaging (Release Ready)

**Deliverables:**
- [ ] Regression test for ts SDK fix (once fixed)
- [ ] Peer cred capture validation (per-emitter type: Go, TS subprocess, Py subprocess)
- [ ] mcp-proxy emitter tests (requires mcp-proxy library exposure or subprocess harness)
- [ ] CI integration: `.github/workflows/daemon.yml` runs `go test -tags=integration ./tests/...`

**Test count:** ~4 tests
**Est. lines of code:** ~300 Go, ~200 Py/TS

---

## Known Issues & Decisions

### The TypeScript Emitter Bug

Current state: The TS SDK emitter is silently broken in v0.8.0-alpha.2. Frames are dropped without error.

**Root cause (hypothesis):** Frames written to socket may be crossing dial timeout or write timeout limits; emitter's fire-and-forget model suppresses the error (correct by design), but the caller has no visibility. Needs actual TS emitter testing against a live daemon to diagnose.

**How Phase 1 addresses this:**
1. Test spawns TS emitter as a subprocess (realistic)
2. Verifies receipt lands in SQLite
3. If receipt is missing, inspect daemon TraceLog to see if frame arrived

Once root cause is identified (socket issue? Node.js net module bug? UTF-8 encoding?), Phase 1 tests will serve as regression suite for the fix.

### Daemon Logging Trade-off

**Trade-off:** Add TraceLog to Config for test visibility vs. maintain silent daemon for security model.

**Decision:** Add TraceLog. It is guarded (nil = silent), so production daemon unaffected. Test framework sets it to a buffer. No security impact; test observers are trusted (running the test suite).

**Alternative:** Do not add TraceLog. Instead, tests inspect SQLite directly (via `store.Open(..., ReadOnly)`) to count receipts and check seq monotonicity. This works for counting but does NOT help diagnose *why* a frame dropped. Root-causing soak test failures becomes painful. Cost of test debugging outweighs benefit of zero logging code in daemon.

### mcp-proxy Emitter (Deferred)

The mcp-proxy's emitter is embedded in the main binary (cmd/main.go wires it). Testing it requires either:
1. Exposing the emitter as a library (refactor, out of scope for Phase 1)
2. Spawning the full mcp-proxy binary (requires MCP server fixture, complex)
3. Deferring to Phase 3 (when mcp-proxy refactor is done)

**Decision:** Phase 1 tests Go, TS, Python SDKs only. mcp-proxy emitter testing deferred to Phase 3.

### openclaw (Deferred)

Similar story: openclaw is external and not in this monorepo. Testing it requires cloning openclaw, spinning up its emitter, and verifying it can connect. Deferred to Phase 3 / separate integration environment.

---

## First Test Implementation Sketch

### Test 1: TS Emitter Single Frame (Catches the v0.8.0-alpha.2 Bug)

**File:** `daemon/tests/emitters/ts_emitter_test.go`

```go
package emitters_test

import (
	"testing"
	"time"
)

// TestTSEmitterSingleFrame verifies the TypeScript SDK emitter can send
// one valid frame to the daemon and produce a stored receipt. This is the
// regression test for v0.8.0-alpha.2 where the TS emitter was silently
// dropping frames (issue #XXX).
func TestTSEmitterSingleFrame(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping emitter integration test in short mode")
	}

	f := startTestDaemon(t)
	defer f.Cleanup()

	// Spawn the TS emitter helper as a subprocess.
	err := f.RunTSEmitter("test-session", map[string]string{
		"tool_name": "list_repos",
		"decision":  "allowed",
	})
	if err != nil {
		t.Fatalf("TS emitter failed: %v", err)
	}

	// Poll for receipt in SQLite.
	receipts, err := f.WaitForReceiptCount("test-session", 1, 5*time.Second)
	if err != nil {
		t.Logf("Daemon trace:\n%s", f.TraceLog())
		t.Fatalf("Expected 1 receipt after TS emitter, got error: %v", err)
	}

	if len(receipts) != 1 {
		t.Fatalf("Expected 1 receipt, got %d", len(receipts))
	}

	// Basic receipt validation.
	r := receipts[0]
	if r.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("First receipt seq = %d, want 1", r.CredentialSubject.Chain.Sequence)
	}
	if r.CredentialSubject.Action.Tool.Name != "list_repos" {
		t.Errorf("Tool name = %q, want %q", r.CredentialSubject.Action.Tool.Name, "list_repos")
	}
	if r.Proof.ProofValue == "" {
		t.Error("Proof signature is empty")
	}
}
```

### Test 2: Concurrent Emitters (Go + TS + Python)

**File:** `daemon/tests/scenarios/concurrent_test.go`

```go
package scenarios_test

import (
	"sync"
	"testing"
	"time"
)

// TestConcurrentSDKEmitters verifies that all three SDK emitters can fire
// frames concurrently and produce a monotonic chain with no gaps or duplicates.
func TestConcurrentSDKEmitters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f := startTestDaemon(t)
	defer f.Cleanup()

	const perEmitter = 5
	const emitters = 3
	total := perEmitter * emitters

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	// Go emitter: direct library call, threaded.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < perEmitter; i++ {
			err := f.RunGoEmitter("go-concurrent", map[string]string{
				"tool_name": "tool_a",
				"decision":  "allowed",
			})
			if err != nil {
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
			}
		}
	}()

	// TS emitter: subprocess, concurrent.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < perEmitter; i++ {
			err := f.RunTSEmitter("ts-concurrent", map[string]string{
				"tool_name": "tool_b",
				"decision":  "denied",
			})
			if err != nil {
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
			}
		}
	}()

	// Python emitter: subprocess, concurrent.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < perEmitter; i++ {
			err := f.RunPyEmitter("py-concurrent", map[string]string{
				"tool_name": "tool_c",
				"decision":  "pending",
			})
			if err != nil {
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
			}
		}
	}()

	wg.Wait()

	if len(errors) > 0 {
		t.Fatalf("Emitter errors: %v", errors)
	}

	// Poll for all receipts.
	receipts, err := f.WaitForReceiptCount("", total, 10*time.Second)
	if err != nil {
		t.Logf("Daemon trace:\n%s", f.TraceLog())
		t.Fatalf("Expected %d receipts, got error: %v", total, err)
	}

	if len(receipts) != total {
		t.Fatalf("Got %d receipts, want %d", len(receipts), total)
	}

	// Validate chain integrity: no gaps, no duplicates, no breaks.
	seen := make(map[int]bool, total)
	for i, r := range receipts {
		seq := r.CredentialSubject.Chain.Sequence
		if seq < 1 || seq > total {
			t.Errorf("Receipt %d has invalid seq %d", i, seq)
			continue
		}
		if seen[seq] {
			t.Errorf("Sequence %d allocated twice", seq)
		}
		seen[seq] = true

		// Validate prev_hash.
		if i == 0 {
			if r.CredentialSubject.Chain.PreviousReceiptHash != nil {
				t.Errorf("First receipt has non-nil prev_hash")
			}
		} else {
			// prev_hash must match hash of receipt at seq-1.
			prevReceipt := receiptBySeq(receipts, seq-1)
			if prevReceipt == nil {
				t.Errorf("Receipt at seq %d missing (needed for prev_hash check)", seq-1)
				continue
			}
			expectedHash, _ := receipt.HashReceipt(*prevReceipt)
			if r.CredentialSubject.Chain.PreviousReceiptHash == nil ||
				*r.CredentialSubject.Chain.PreviousReceiptHash != expectedHash {
				t.Errorf("Receipt %d: prev_hash mismatch", seq)
			}
		}
	}

	// Check for gaps.
	for i := 1; i <= total; i++ {
		if !seen[i] {
			t.Errorf("Missing receipt at seq %d", i)
		}
	}
}

func receiptBySeq(receipts []receipt.AgentReceipt, seq int) *receipt.AgentReceipt {
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence == seq {
			return &receipts[i]
		}
	}
	return nil
}
```

### Subprocess Helper: TypeScript

**File:** `daemon/tests/fixtures/emitter_helpers/ts_emitter.js`

```javascript
const { Emitter } = require("@agnt-rcpt/sdk-ts");

const socketPath = process.env.AGENTRECEIPTS_SOCKET;
const sessionId = process.env.TEST_SESSION_ID || "ts-helper";
const toolName = process.env.TEST_TOOL_NAME || "helper";
const decision = process.env.TEST_DECISION || "allowed";
const input = process.env.TEST_INPUT || null;
const output = process.env.TEST_OUTPUT || null;

async function main() {
  const emitter = new Emitter({ socketPath, sessionId });
  try {
    const err = await emitter.emit({
      channel: "test",
      tool: { name: toolName },
      input,
      output,
      decision,
    });
    if (err) {
      console.error(`emit failed: ${err.message}`);
      process.exit(1);
    }
  } finally {
    emitter.close();
  }
}

main();
```

---

## Success Criteria

1. **Soak test blocking issue resolved:** Phase 1 tests include a TS emitter test that either passes (if TS emitter is already fixed) or fails clearly (if the v0.8.0-alpha.2 bug is present). The test failure includes daemon trace showing exactly where the frame dropped.

2. **All emitters validated:** Phase 1 covers Go, TS, Python SDK emitters. Each has a single-frame test and a concurrent test.

3. **Chain integrity validated:** Concurrent tests verify no gaps, no duplicates, correct seq and prev_hash, valid signatures.

4. **Daemon robustness:** Phase 2 covers daemon restart, protocol errors, timeout behavior. Daemon does not crash or corrupt the chain.

5. **Regression prevention:** Once TS emitter is fixed, the test suite serves as regression suite. Future changes to any emitter run the same tests and fail if they reintroduce dropping.

6. **CI integration:** Tests run in `.github/workflows/daemon.yml` as part of the daemon CI pipeline.

---

## Open Questions for Discussion

1. **Should Phase 1 include TraceLog implementation in daemon.go, or defer observability to a later PR?**
   - Pro defer: Simpler Phase 1, focus on tests.
   - Pro include: Allows tests to self-diagnose failures (inspect trace when receipts missing).
   - Recommendation: Defer. Phase 1 tests can detect failures (missing receipts) without root cause. If root cause is needed, add TraceLog in a follow-up.

2. **Should subprocess emitters be built and committed, or compiled at test time?**
   - Pro build: Faster tests (no compile), simpler debugging.
   - Pro compile: Avoids stale binaries, auto-builds on source change.
   - Recommendation: Compile at test time (like cross-sdk-tests does). Use `go:embed` for simple helpers; for TS/Py, spawn `npm run build` / `uv run pyright` first.

3. **mcp-proxy & openclaw timing: Block on them for Phase 1, or scope them to Phase 3?**
   - Recommendation: Phase 3. mcp-proxy requires refactor to expose emitter as library. openclaw is external. Phase 1 tests 3 SDKs and proves the harness works.

4. **Should the test suite live in daemon/tests/ (as proposed) or daemon/integration_tests/ (parallel to existing integration_test.go)?**
   - Recommendation: Simplify to `daemon/tests/` directory. Move existing `daemon/integration_test.go` to `daemon/daemon_test.go` (unit tests live with the code). New integration tests go in `daemon/tests/`.

