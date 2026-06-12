package main

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// persistenceOrSigningPattern matches packages that would turn obsigna-mcp into
// a receipt writer instead of a thin emitter. ADR-0010 makes the daemon the sole
// writer — it owns redaction, hashing, signing, chaining, and persistence — and
// the proxy only forwards completed events over a socket (sdk/go/emitter). This
// gate (ADR-0033's Gate A) makes that boundary structural rather than a
// convention: the proxy's production import graph must never reach
//
//   - the receipt store (sdk/go/store) or any SQLite driver — no local store
//     (the "do not reintroduce a local store" rule, ADR-0010);
//   - receipt construction/signing (sdk/go/receipt) — the proxy must not build
//     or sign receipts; it emits events and the daemon signs them;
//   - the daemon library itself (ar/daemon…) — the proxy is a separate process,
//     not a linked-in daemon.
//
// Unlike the daemon's Gate A, the rationale is not "code next to the private
// key" (the proxy holds no key) but "one writer, enforced at the binary
// boundary" — the same one-principal/one-responsibility-per-process argument
// ADR-0032 makes for the proxy's transport.
//
// google/uuid pulls in database/sql/driver (it implements driver.Valuer); that
// is an interface-only package with no DB engine behind it, so it is allowed —
// the pattern targets sdk/go/store, sdk/go/receipt, the daemon, and real SQLite
// drivers, not the driver interfaces.
var persistenceOrSigningPattern = regexp.MustCompile(
	`^(` +
		`github\.com/agent-receipts/ar/sdk/go/(store|receipt)` +
		`|github\.com/agent-receipts/ar/daemon(/.*)?` +
		`|modernc\.org/sqlite` +
		`|github\.com/mattn/go-sqlite3` +
		`)$`,
)

// TestImportGraphExcludesPersistenceAndSigning is Gate A (ADR-0033): obsigna-mcp
// stays a thin emitter. A dependency edge into the store, a SQLite driver,
// receipt signing, or the daemon library would mean the proxy had grown writer
// responsibilities that ADR-0010 reserves for the daemon. Keying on packages
// (not an enumerated allowlist) means a future reintroduction of a local store
// is caught automatically. The proxy legitimately depends on internal/{audit,
// host,policy,proxy} and sdk/go/emitter — none of which match.
//
// This is the source of truth for Gate A; the mcp-proxy.yml import-graph job
// just runs this test so the rule lives in one place next to the code it guards.
func TestImportGraphExcludesPersistenceAndSigning(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	var offenders []string
	for _, dep := range strings.Fields(string(out)) {
		if persistenceOrSigningPattern.MatchString(dep) {
			offenders = append(offenders, dep)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("obsigna-mcp imports persistence/signing package(s) %v; ADR-0033 keeps the proxy a thin emitter — the daemon is the sole receipt writer (ADR-0010). Forward events via sdk/go/emitter instead of constructing, signing, or storing receipts in-process", offenders)
	}
}
