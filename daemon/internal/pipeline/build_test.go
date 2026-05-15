package pipeline

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/chain"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

func newTestKeySource(t *testing.T) keysource.KeySource {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	ks := keysource.NewFile(path, "did:agent-receipts-daemon:test#k1")
	if err := ks.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ks.Teardown() })
	return ks
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleFrame(t *testing.T) socket.Frame {
	t.Helper()
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "sess-123",
		Channel:   "mcp_proxy",
		Tool:      EmitterTool{Server: "github", Name: "list_repos"},
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	return socket.Frame{
		Payload: body,
		Peer: socket.PeerCred{
			Platform: "linux",
			PID:      4242,
			UID:      1000,
			GID:      1000,
			ExePath:  "/usr/bin/mcp-proxy",
		},
	}
}

func TestProcess_BuildsSignedReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}

	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chainReceipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(chainReceipts))
	}
	r := chainReceipts[0]

	if r.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("seq = %d, want 1", r.CredentialSubject.Chain.Sequence)
	}
	if r.CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Errorf("first receipt prev_hash = %v, want nil", r.CredentialSubject.Chain.PreviousReceiptHash)
	}
	if r.CredentialSubject.Action.Type != "mcp_proxy.github.list_repos" {
		t.Errorf("action.type = %q", r.CredentialSubject.Action.Type)
	}
	if r.CredentialSubject.Action.ToolName != "list_repos" {
		t.Errorf("action.tool_name = %q", r.CredentialSubject.Action.ToolName)
	}
	pd := r.CredentialSubject.Action.ParametersDisclosure
	if pd["peer.platform"] != "linux" || pd["peer.pid"] != "4242" || pd["peer.uid"] != "1000" {
		t.Errorf("peer attestation not recorded: %#v", pd)
	}
	if pd["peer.exe_path"] != "/usr/bin/mcp-proxy" {
		t.Errorf("peer.exe_path = %q", pd["peer.exe_path"])
	}
	// session_id, channel, ts_emit must NOT be in parameters_disclosure —
	// they live on issuer.session_id / action.type / (dropped) respectively.
	for _, k := range []string{"session_id", "channel", "ts_emit", "ts_recv", "error"} {
		if _, ok := pd[k]; ok {
			t.Errorf("parameters_disclosure unexpectedly contains %q (emitter content must not be mirrored here)", k)
		}
	}
	if r.Issuer.SessionID != "sess-123" {
		t.Errorf("issuer.session_id = %q, want sess-123", r.Issuer.SessionID)
	}

	pubPEM, err := ks.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := receipt.Verify(r, pubPEM)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if !ok {
		t.Error("signature did not verify")
	}
}

func TestProcess_OutcomeStatus(t *testing.T) {
	cases := []struct {
		name       string
		decision   string
		errorField string
		want       receipt.OutcomeStatus
	}{
		{"allowed no error", "allowed", "", receipt.StatusSuccess},
		{"allowed with error", "allowed", "upstream timeout", receipt.StatusFailure},
		{"denied", "denied", "", receipt.StatusFailure},
		{"pending", "pending", "", receipt.StatusPending},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks := newTestKeySource(t)
			st := newTestStore(t)
			state := chain.New("chain-1")
			p := New(state, ks, st, "did:agent-receipts-daemon:test")

			body, err := json.Marshal(EmitterFrame{
				Version:   "1",
				TsEmit:    "2026-05-03T00:00:00Z",
				SessionID: "s",
				Channel:   "sdk",
				Tool:      EmitterTool{Name: "t"},
				Decision:  tc.decision,
				Error:     tc.errorField,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Process(socket.Frame{Payload: body}); err != nil {
				t.Fatalf("Process: %v", err)
			}
			receipts, err := st.GetChain("chain-1")
			if err != nil {
				t.Fatal(err)
			}
			got := receipts[0].CredentialSubject.Outcome.Status
			if got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProcess_AdvancesSequenceAndPrevHash(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	for i := 0; i < 3; i++ {
		if err := p.Process(sampleFrame(t)); err != nil {
			t.Fatalf("Process %d: %v", i, err)
		}
	}

	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chainReceipts) != 3 {
		t.Fatalf("got %d receipts, want 3", len(chainReceipts))
	}
	for i, r := range chainReceipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
	if chainReceipts[0].CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Error("receipt 0: prev_hash should be nil")
	}
	for i := 1; i < len(chainReceipts); i++ {
		want, err := receipt.HashReceipt(chainReceipts[i-1])
		if err != nil {
			t.Fatal(err)
		}
		got := chainReceipts[i].CredentialSubject.Chain.PreviousReceiptHash
		if got == nil || *got != want {
			t.Errorf("receipt %d: prev_hash = %v, want %s", i, got, want)
		}
	}
}

func TestProcess_RiskLevelFromTaxonomy(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// The daemon constructs action.type as "<channel>.<server>.<name>" or
	// "<channel>.<name>". None of those match the built-in taxonomy, so
	// receipts MUST come out as RiskMedium (UnknownAction's risk) rather
	// than RiskLow (the previous hardcoded default).
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := chainReceipts[0].CredentialSubject.Action.RiskLevel, receipt.RiskMedium; got != want {
		t.Errorf("unknown action_type risk = %q, want %q (taxonomy unknown default)", got, want)
	}
}

func TestProcess_AcceptsExplicitNullInputOutput(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// "input": null and "output": null are the documented wire form for events
	// that genuinely have no payload (see daemon/README.md). They MUST be
	// accepted as equivalent to absent — and MUST NOT produce hashes (a hash
	// of literal null would falsely commit the daemon to "the input was null"
	// vs. "no input was sent").
	payload := []byte(`{"v":"1","ts_emit":"2026-05-03T00:00:00Z","session_id":"s","channel":"sdk","tool":{"name":"noop"},"input":null,"output":null,"decision":"allowed"}`)
	if err := p.Process(socket.Frame{Payload: payload}); err != nil {
		t.Fatalf("frame with explicit null input/output should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]
	if r.CredentialSubject.Action.ParametersHash != "" {
		t.Errorf("null input must not produce parameters_hash, got %q", r.CredentialSubject.Action.ParametersHash)
	}
	if r.CredentialSubject.Outcome.ResponseHash != "" {
		t.Errorf("null output must not produce response_hash, got %q", r.CredentialSubject.Outcome.ResponseHash)
	}
}

func TestProcess_HashesInput(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	input := json.RawMessage(`{"path":"/etc/passwd","mode":"r"}`)
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Input:     input,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("frame with input should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]

	// Recompute the expected hash via the same canonicalization path the
	// receipt.Create helper uses — no shortcut through the daemon's internals.
	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		t.Fatal(err)
	}
	canonical, err := receipt.Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	want := receipt.SHA256Hash(canonical)
	if got := r.CredentialSubject.Action.ParametersHash; got != want {
		t.Errorf("parameters_hash = %q, want %q", got, want)
	}
}

func TestProcess_HashesOutput(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	output := json.RawMessage(`{"bytes":1024,"checksum":"sha256:abc"}`)
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Output:    output,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("frame with output should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]

	var v any
	if err := json.Unmarshal(output, &v); err != nil {
		t.Fatal(err)
	}
	canonical, err := receipt.Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	want := receipt.SHA256Hash(canonical)
	if got := r.CredentialSubject.Outcome.ResponseHash; got != want {
		t.Errorf("response_hash = %q, want %q", got, want)
	}
}

func TestProcess_HashesAreCanonical(t *testing.T) {
	// Same logical payload sent two different ways (key order, whitespace) MUST
	// produce identical hashes — that's the property cross-language verifiers
	// rely on. If this test ever fails, the canonicalizer regressed and every
	// SDK that ever produced a hash is at risk of mismatch.
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	frameA, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Input:     json.RawMessage(`{"a":1,"b":2,"c":3}`),
		Output:    json.RawMessage(`{"x":[1,2,3],"y":"ok"}`),
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	frameB, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Input:     json.RawMessage(`{ "c":3, "b":2 ,  "a":1 }`),
		Output:    json.RawMessage("{\n  \"y\":\"ok\",\n  \"x\":[1, 2, 3]\n}"),
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: frameA}); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: frameB}); err != nil {
		t.Fatal(err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chainReceipts) != 2 {
		t.Fatalf("got %d receipts, want 2", len(chainReceipts))
	}
	a, b := chainReceipts[0], chainReceipts[1]
	if a.CredentialSubject.Action.ParametersHash != b.CredentialSubject.Action.ParametersHash {
		t.Errorf("parameters_hash differs across whitespace/key-order variants:\n  a=%q\n  b=%q",
			a.CredentialSubject.Action.ParametersHash, b.CredentialSubject.Action.ParametersHash)
	}
	if a.CredentialSubject.Outcome.ResponseHash != b.CredentialSubject.Outcome.ResponseHash {
		t.Errorf("response_hash differs across whitespace/key-order variants:\n  a=%q\n  b=%q",
			a.CredentialSubject.Outcome.ResponseHash, b.CredentialSubject.Outcome.ResponseHash)
	}
}

func TestProcess_AcceptsPrimitiveInputOutput(t *testing.T) {
	// MCP tool inputs are typically JSON objects, but tool outputs are
	// commonly strings, numbers, or arrays. The wire schema MUST accept any
	// valid JSON value and hash it consistently.
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "echo"},
		Input:     json.RawMessage(`"hello"`),
		Output:    json.RawMessage(`["a","b"]`),
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("primitive input + array output should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]
	if r.CredentialSubject.Action.ParametersHash == "" {
		t.Error("primitive input must produce a parameters_hash")
	}
	if r.CredentialSubject.Outcome.ResponseHash == "" {
		t.Error("array output must produce a response_hash")
	}
}

func TestProcess_RejectsUnrepresentableNumbers(t *testing.T) {
	// 1e400 is syntactically valid JSON, so it survives the EmitterFrame
	// unmarshal (json.RawMessage stores the token verbatim without numeric
	// parsing). Re-unmarshaling into Go's `any` for canonicalisation fails
	// because the value overflows float64. The daemon MUST surface that as a
	// per-frame error and keep running — a panic here would let any
	// authenticated emitter DoS the daemon for every other emitter on the
	// same socket.
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	cases := []struct {
		name    string
		payload []byte
	}{
		{"input is unrepresentable number", []byte(`{"v":"1","ts_emit":"2026-05-03T00:00:00Z","session_id":"s","channel":"sdk","tool":{"name":"t"},"input":1e400,"decision":"allowed"}`)},
		{"output is unrepresentable number", []byte(`{"v":"1","ts_emit":"2026-05-03T00:00:00Z","session_id":"s","channel":"sdk","tool":{"name":"t"},"output":1e400,"decision":"allowed"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Process panicked on %s — daemon would crash: %v", tc.name, r)
				}
			}()
			if err := p.Process(socket.Frame{Payload: tc.payload}); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}

	// Chain state must NOT have advanced — error before persist means
	// alloc.Rollback ran on every case.
	a := state.Allocate()
	defer a.Rollback()
	if a.Sequence != 1 {
		t.Errorf("after rejected frames, next seq = %d, want 1 (no advance)", a.Sequence)
	}
}

// panicSigningKeySource panics on Sign, simulating any unexpected runtime
// failure between Allocate and Commit. Used to prove pipeline.Process releases
// the chain mutex via deferred Rollback even when buildAndSign panics.
type panicSigningKeySource struct{}

func (panicSigningKeySource) Init() error                  { return nil }
func (panicSigningKeySource) Teardown() error              { return nil }
func (panicSigningKeySource) PublicKey() (string, error)   { return "", nil }
func (panicSigningKeySource) VerificationMethod() string   { return "did:test#k1" }
func (panicSigningKeySource) Rotate() error                { return nil }
func (panicSigningKeySource) Sign(_ []byte) ([]byte, error) {
	panic("simulated panic during signing")
}

func TestProcess_PanicReleasesChainAllocation(t *testing.T) {
	// Any panic between Allocate and Commit MUST release the chain mutex via
	// the deferred Rollback. Without that, a single bad frame would deadlock
	// the daemon for every subsequent emitter on the same socket.
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, panicSigningKeySource{}, st, "did:agent-receipts-daemon:test")

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected Process to panic with the panicSigningKeySource stub; setup is broken")
			}
		}()
		_ = p.Process(sampleFrame(t))
	}()

	// If the chain mutex is still held, the next Allocate would block forever.
	// Run it on a goroutine with a tight timeout so the test fails loudly
	// rather than hanging until the framework's default kill.
	done := make(chan struct{})
	go func() {
		a := state.Allocate()
		a.Rollback()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("chain.State.Allocate timed out: panic in buildAndSign orphaned the mutex")
	}
}

func TestProcess_DaemonControlsAllTimestamps(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	fixed := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	p.Now = func() time.Time { return fixed }

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]

	want := fixed.Format(time.RFC3339)
	if r.IssuanceDate != want {
		t.Errorf("issuanceDate = %q, want %q (Now hook should govern all daemon-stamped timestamps)", r.IssuanceDate, want)
	}
	if r.CredentialSubject.Action.Timestamp != want {
		t.Errorf("action.timestamp = %q, want %q", r.CredentialSubject.Action.Timestamp, want)
	}
	if r.Proof.Created != want {
		t.Errorf("proof.created = %q, want %q", r.Proof.Created, want)
	}
}

func TestProcess_RejectsMalformedFrames(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// All cases below include ts_emit where it's not the field under test, so
	// validateFrame doesn't short-circuit on the new ts_emit check before
	// reaching the field we're actually exercising.
	const ok = `"ts_emit":"2026-05-04T00:00:00Z"`
	cases := []struct {
		name    string
		payload string
	}{
		{"not JSON", `not json`},
		{"missing v", `{` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"unsupported v", `{"v":"2",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing session_id", `{"v":"1",` + ok + `,"channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing ts_emit", `{"v":"1","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"malformed ts_emit", `{"v":"1","ts_emit":"yesterday","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing tool.name", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{},"decision":"allowed"}`},
		{"missing decision", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"}}`},
		{"unknown decision", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"maybe"}`},
		{"negative drop_count", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed","drop_count":-1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Process(socket.Frame{Payload: []byte(tc.payload)})
			if err == nil {
				t.Error("expected error")
			}
		})
	}

	// All rejected — chain state must NOT have advanced.
	a := state.Allocate()
	defer a.Rollback()
	if a.Sequence != 1 {
		t.Errorf("after rejected frames, next seq = %d, want 1 (no advance)", a.Sequence)
	}
}

func dropFrame(t *testing.T, dropCount int64) socket.Frame {
	t.Helper()
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "sess-drop",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "op"},
		Decision:  "allowed",
		DropCount: dropCount,
	})
	if err != nil {
		t.Fatal(err)
	}
	return socket.Frame{
		Payload: body,
		Peer:    socket.PeerCred{Platform: "linux", PID: 99, UID: 1000, GID: 1000, ExePath: "/usr/bin/emitter"},
	}
}

// TestProcess_DropCountZero verifies that when drop_count is absent (zero),
// Process inserts exactly one receipt and the chain starts at sequence 1.
func TestProcess_DropCountZero(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1 (no synthetic receipt for zero drop_count)", len(receipts))
	}
	if receipts[0].CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("seq = %d, want 1", receipts[0].CredentialSubject.Chain.Sequence)
	}
}

// TestProcess_DropCountInsertsEventsDroppedReceipt verifies the core
// events_dropped guarantee: when drop_count > 0 the daemon inserts a synthetic
// receipt at the current chain slot before the live receipt, so the gap is
// visible in the chain with no missing sequences.
func TestProcess_DropCountInsertsEventsDroppedReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(dropFrame(t, 3)); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatalf("got %d receipts, want 2 (synthetic + live)", len(receipts))
	}

	synthetic := receipts[0]
	live := receipts[1]

	// Synthetic receipt at seq 1.
	if synthetic.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("synthetic seq = %d, want 1", synthetic.CredentialSubject.Chain.Sequence)
	}
	if synthetic.CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Errorf("synthetic first-in-chain: prev_hash should be nil")
	}
	if got := synthetic.CredentialSubject.Action.Type; got != actionTypeEventsDropped {
		t.Errorf("synthetic action.type = %q, want %q", got, actionTypeEventsDropped)
	}
	if got := synthetic.CredentialSubject.Action.ToolName; got != "events_dropped" {
		t.Errorf("synthetic tool_name = %q, want events_dropped", got)
	}
	if got := synthetic.CredentialSubject.Action.RiskLevel; got != "low" {
		t.Errorf("synthetic risk_level = %q, want low", got)
	}
	if got := synthetic.CredentialSubject.Outcome.Status; got != "success" {
		t.Errorf("synthetic outcome.status = %q, want success", got)
	}
	if got := synthetic.CredentialSubject.Action.ParametersDisclosure["drop_count"]; got != "3" {
		t.Errorf("synthetic drop_count disclosure = %q, want 3", got)
	}
	if got := synthetic.Issuer.SessionID; got != "sess-drop" {
		t.Errorf("synthetic session_id = %q, want sess-drop", got)
	}

	// Live receipt at seq 2, prev_hash pointing to synthetic.
	if live.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("live seq = %d, want 2", live.CredentialSubject.Chain.Sequence)
	}
	wantPrev, err := receipt.HashReceipt(synthetic)
	if err != nil {
		t.Fatalf("hash synthetic: %v", err)
	}
	if live.CredentialSubject.Chain.PreviousReceiptHash == nil || *live.CredentialSubject.Chain.PreviousReceiptHash != wantPrev {
		t.Errorf("live prev_hash = %v, want %s", live.CredentialSubject.Chain.PreviousReceiptHash, wantPrev)
	}
	if live.CredentialSubject.Action.Type != "sdk.op" {
		t.Errorf("live action.type = %q, want sdk.op", live.CredentialSubject.Action.Type)
	}

	// Both receipts must be verifiable — the synthetic receipt uses the same
	// signer as the live one.
	pubPEM, err := ks.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range receipts {
		ok, err := receipt.Verify(r, pubPEM)
		if err != nil || !ok {
			t.Errorf("receipt[%d]: verify ok=%v err=%v", i, ok, err)
		}
	}
}

// TestProcess_DropCountPreservesPeerAttestationOnSynthetic verifies that the
// peer cred from the emitter connection is recorded in the synthetic receipt's
// parameters_disclosure, matching the live receipt's attribution source.
func TestProcess_DropCountPreservesPeerAttestationOnSynthetic(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(dropFrame(t, 1)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) < 1 {
		t.Fatal("no receipts")
	}
	pd := receipts[0].CredentialSubject.Action.ParametersDisclosure
	if pd["peer.platform"] != "linux" {
		t.Errorf("peer.platform = %q, want linux", pd["peer.platform"])
	}
	if pd["peer.pid"] != "99" {
		t.Errorf("peer.pid = %q, want 99", pd["peer.pid"])
	}
	if pd["peer.exe_path"] != "/usr/bin/emitter" {
		t.Errorf("peer.exe_path = %q", pd["peer.exe_path"])
	}
}

// TestProcess_DropCountChainContinues verifies that a frame with a drop_count
// followed by a normal frame (no drops) produces a clean contiguous chain
// with correct prev_hash links across all three receipts.
func TestProcess_DropCountChainContinues(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(dropFrame(t, 2)); err != nil {
		t.Fatalf("Process (drop frame): %v", err)
	}
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatalf("Process (normal frame): %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 3 {
		t.Fatalf("got %d receipts, want 3 (synthetic + live + normal)", len(receipts))
	}
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipts[%d].Sequence = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
	for i := 1; i < len(receipts); i++ {
		want, err := receipt.HashReceipt(receipts[i-1])
		if err != nil {
			t.Fatalf("hash receipt %d: %v", i-1, err)
		}
		got := receipts[i].CredentialSubject.Chain.PreviousReceiptHash
		if got == nil || *got != want {
			t.Errorf("receipts[%d] prev_hash = %v, want %s", i, got, want)
		}
	}
}

// failOnNthInsert wraps a ReceiptStore and returns an error on the Nth Insert.
type failOnNthInsert struct {
	store.ReceiptStore
	n       int
	callNum int
}

func (f *failOnNthInsert) Insert(r receipt.AgentReceipt, hash string) error {
	f.callNum++
	if f.callNum == f.n {
		return fmt.Errorf("simulated store insert failure on call %d", f.n)
	}
	return f.ReceiptStore.Insert(r, hash)
}

// TestProcess_DropCountSyntheticFailureLiveReceiptPersists verifies that when
// the synthetic events_dropped receipt fails to persist, the live receipt is
// still written to the store. The synthetic insert error is returned by
// Process so the socket listener can log it, but the live event is not lost.
func TestProcess_DropCountSyntheticFailureLiveReceiptPersists(t *testing.T) {
	ks := newTestKeySource(t)
	underlying := newTestStore(t)
	// Fail only the first Insert (the synthetic receipt); the second (live) must succeed.
	st := &failOnNthInsert{ReceiptStore: underlying, n: 1}

	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	err := p.Process(dropFrame(t, 2))
	if err == nil {
		t.Error("expected error from synthetic insert failure, got nil")
	}

	// Live receipt must still be in the store despite the synthetic failure.
	receipts, getErr := underlying.GetChain("chain-1")
	if getErr != nil {
		t.Fatalf("GetChain: %v", getErr)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1 (live receipt must survive synthetic failure)", len(receipts))
	}
	if got := receipts[0].CredentialSubject.Action.Type; got != "sdk.op" {
		t.Errorf("action.type = %q, want sdk.op", got)
	}
	if got := receipts[0].CredentialSubject.Chain.Sequence; got != 1 {
		t.Errorf("seq = %d, want 1 (chain advanced past failed synthetic slot)", got)
	}
}
