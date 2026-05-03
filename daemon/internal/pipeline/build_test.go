package pipeline

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

	// "input": null and "output": null are the documented Phase 1 wire form
	// (see daemon/README.md). They MUST be accepted as equivalent to absent.
	payload := []byte(`{"v":"1","ts_emit":"2026-05-03T00:00:00Z","session_id":"s","channel":"sdk","tool":{"name":"noop"},"input":null,"output":null,"decision":"allowed"}`)
	if err := p.Process(socket.Frame{Payload: payload}); err != nil {
		t.Fatalf("frame with explicit null input/output should be accepted: %v", err)
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

	cases := []struct {
		name    string
		payload string
	}{
		{"not JSON", `not json`},
		{"missing v", `{"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"unsupported v", `{"v":"2","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing session_id", `{"v":"1","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing tool.name", `{"v":"1","session_id":"s","channel":"sdk","tool":{},"decision":"allowed"}`},
		{"missing decision", `{"v":"1","session_id":"s","channel":"sdk","tool":{"name":"t"}}`},
		{"unknown decision", `{"v":"1","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"maybe"}`},
		{"input present (Phase 1 forbidden)", `{"v":"1","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed","input":{"x":1}}`},
		{"output present (Phase 1 forbidden)", `{"v":"1","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed","output":{"y":2}}`},
		{"input as primitive (Phase 1 forbidden)", `{"v":"1","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed","input":"hello"}`},
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
