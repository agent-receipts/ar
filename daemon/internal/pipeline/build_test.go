package pipeline

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestBuildPeerCred covers the pointer-semantics of buildPeerCred: POSIX
// platforms must set UID/GID to non-nil pointers (including for zero/root),
// and non-POSIX platforms must leave both nil.
func TestBuildPeerCred(t *testing.T) {
	cases := []struct {
		name     string
		peer     socket.PeerCred
		wantUID  *uint32
		wantGID  *uint32
		wantNil  bool
	}{
		{
			name:    "linux non-root",
			peer:    socket.PeerCred{Platform: "linux", PID: 42, UID: 1000, GID: 1000},
			wantUID: ptrUint32(1000),
			wantGID: ptrUint32(1000),
		},
		{
			name:    "linux root (uid=0 must not be dropped)",
			peer:    socket.PeerCred{Platform: "linux", PID: 1, UID: 0, GID: 0},
			wantUID: ptrUint32(0),
			wantGID: ptrUint32(0),
		},
		{
			name:    "darwin",
			peer:    socket.PeerCred{Platform: "darwin", PID: 99, UID: 501, GID: 20},
			wantUID: ptrUint32(501),
			wantGID: ptrUint32(20),
		},
		{
			name:    "non-POSIX platform (no UID concept)",
			peer:    socket.PeerCred{Platform: "windows", PID: 7, UID: 0, GID: 0},
			wantNil: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := buildPeerCred(tc.peer)
			if pc == nil {
				t.Fatal("buildPeerCred returned nil")
			}
			if tc.wantNil {
				if pc.UID != nil {
					t.Errorf("UID = %v, want nil on non-POSIX platform", pc.UID)
				}
				if pc.GID != nil {
					t.Errorf("GID = %v, want nil on non-POSIX platform", pc.GID)
				}
				return
			}
			if pc.UID == nil || *pc.UID != *tc.wantUID {
				t.Errorf("UID = %v, want %d", pc.UID, *tc.wantUID)
			}
			if pc.GID == nil || *pc.GID != *tc.wantGID {
				t.Errorf("GID = %v, want %d", pc.GID, *tc.wantGID)
			}
		})
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
	pc := r.CredentialSubject.Action.PeerCredential
	if pc == nil {
		t.Fatal("PeerCredential nil; daemon must record OS-attested peer cred on every live receipt")
	}
	if pc.Platform != "linux" || pc.PID != 4242 || pc.UID == nil || *pc.UID != 1000 {
		t.Errorf("peer attestation not recorded: %#v", pc)
	}
	if pc.ExePath != "/usr/bin/mcp-proxy" {
		t.Errorf("peer_credential.exe_path = %q", pc.ExePath)
	}
	// Live receipts MUST NOT carry the synthetic emitter_metadata block —
	// drop_count belongs to events_dropped synthetic receipts only.
	if r.CredentialSubject.Action.EmitterMetadata != nil {
		t.Errorf("live receipt should not carry emitter_metadata; got %#v", r.CredentialSubject.Action.EmitterMetadata)
	}
	// parameters_disclosure stays nil until the daemon ships envelope-mode
	// disclosure (issue #280); the old plaintext-in-body shape is gone.
	if r.CredentialSubject.Action.ParametersDisclosure != nil {
		t.Errorf("ParametersDisclosure must be nil on plain live receipts; got %#v", r.CredentialSubject.Action.ParametersDisclosure)
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

// TestProcess_StampsIdempotencyKey verifies the daemon copies the frame's
// idempotency_key onto action.idempotency_key (spec §7.3.6, #480) and omits it
// when the frame leaves it empty.
func TestProcess_StampsIdempotencyKey(t *testing.T) {
	build := func(t *testing.T, key string) receipt.Action {
		t.Helper()
		ks := newTestKeySource(t)
		st := newTestStore(t)
		state := chain.New("chain-1")
		p := New(state, ks, st, "did:agent-receipts-daemon:test")
		body, err := json.Marshal(EmitterFrame{
			Version:        "1",
			TsEmit:         "2026-05-23T00:00:00Z",
			SessionID:      "s",
			Channel:        "mcp",
			Tool:           EmitterTool{Name: "do_thing"},
			Decision:       "allowed",
			IdempotencyKey: key,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Process(socket.Frame{Payload: body}); err != nil {
			t.Fatal(err)
		}
		chainReceipts, err := st.GetChain("chain-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(chainReceipts) != 1 {
			t.Fatalf("got %d receipts, want 1", len(chainReceipts))
		}
		return chainReceipts[0].CredentialSubject.Action
	}

	t.Run("present", func(t *testing.T) {
		if got := build(t, "jsonrpc-req-99").IdempotencyKey; got != "jsonrpc-req-99" {
			t.Errorf("action.idempotency_key = %q, want %q", got, "jsonrpc-req-99")
		}
	})
	t.Run("absent", func(t *testing.T) {
		if got := build(t, "").IdempotencyKey; got != "" {
			t.Errorf("action.idempotency_key = %q, want empty", got)
		}
	})
}

// TestValidateFrame_RejectsOversizeIdempotencyKey pins the per-field cap so a
// runaway idempotency_key cannot inflate receipts.
func TestValidateFrame_RejectsOversizeIdempotencyKey(t *testing.T) {
	f := &EmitterFrame{
		Version:        "1",
		SessionID:      "s",
		Channel:        "mcp",
		Tool:           EmitterTool{Name: "t"},
		Decision:       "allowed",
		IdempotencyKey: strings.Repeat("x", maxIdentityFieldLen+1),
	}
	if err := validateFrame(f); err == nil {
		t.Error("validateFrame accepted an oversize idempotency_key; want rejection")
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

// TestProcess_MCPIsErrorOutcome covers the MCP CallToolResult envelope: a
// JSON-RPC call that returns successfully but whose result body sets
// "isError": true is a tool-level failure. The proxy reports it with
// decision="allowed" and an empty error field (no JSON-RPC error was
// returned), so the daemon must inspect the result body to derive
// outcome.status. Non-mcp channels must keep their existing mapping —
// other channels may use isError with different semantics.
func TestProcess_MCPIsErrorOutcome(t *testing.T) {
	mcpErrorOutput := json.RawMessage(`{"content":[{"type":"text","text":"401 Bad credentials"}],"isError":true}`)
	mcpOKOutput := json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`)
	mcpImplicitOKOutput := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)

	cases := []struct {
		name    string
		channel string
		output  json.RawMessage
		want    receipt.OutcomeStatus
	}{
		{"mcp isError true → failure", "mcp", mcpErrorOutput, receipt.StatusFailure},
		{"mcp isError false → success", "mcp", mcpOKOutput, receipt.StatusSuccess},
		{"mcp isError absent → success", "mcp", mcpImplicitOKOutput, receipt.StatusSuccess},
		{"mcp empty output → success", "mcp", nil, receipt.StatusSuccess},
		{"mcp non-object output → success (no escalation on parse failure)", "mcp", json.RawMessage(`"not-an-object"`), receipt.StatusSuccess},
		// Other channels must not be reinterpreted: a top-level isError
		// field there is not the MCP envelope.
		{"non-mcp channel with isError true → success", "sdk", mcpErrorOutput, receipt.StatusSuccess},
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
				Channel:   tc.channel,
				Tool:      EmitterTool{Server: "github", Name: "create_pull_request"},
				Output:    tc.output,
				Decision:  "allowed",
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

func (panicSigningKeySource) Init() error                { return nil }
func (panicSigningKeySource) Teardown() error            { return nil }
func (panicSigningKeySource) PublicKey() (string, error) { return "", nil }
func (panicSigningKeySource) VerificationMethod() string { return "did:test#k1" }
func (panicSigningKeySource) Rotate() error              { return nil }
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
	em := synthetic.CredentialSubject.Action.EmitterMetadata
	if em == nil {
		t.Fatal("synthetic events_dropped receipt missing emitter_metadata")
	}
	if em.DropCount != 3 {
		t.Errorf("synthetic emitter_metadata.drop_count = %d, want 3", em.DropCount)
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
// peer_credential, matching the live receipt's attribution source.
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
	pc := receipts[0].CredentialSubject.Action.PeerCredential
	if pc == nil {
		t.Fatal("synthetic receipt missing peer_credential")
	}
	if pc.Platform != "linux" {
		t.Errorf("peer_credential.platform = %q, want linux", pc.Platform)
	}
	if pc.PID != 99 {
		t.Errorf("peer_credential.pid = %d, want 99", pc.PID)
	}
	if pc.ExePath != "/usr/bin/emitter" {
		t.Errorf("peer_credential.exe_path = %q", pc.ExePath)
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

// TestProcess_ParameterDisclosureFlagIsNoOp verifies that the legacy
// --parameter-disclosure opt-in is a no-op as of the v0.3.0 envelope migration
// (ADR-0012 amendment 2026-05-18). The receipt type only accepts the HPKE
// envelope shape now, so plaintext-in-body input/output has nowhere to go.
// The flag stays in place so operators do not see a sudden config error, but
// it must not produce a parameters_disclosure value in either direction.
// Encrypted disclosure is tracked in #280.
func TestProcess_ParameterDisclosureFlagIsNoOp(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
	}{
		{"enabled", true},
		{"disabled", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks := newTestKeySource(t)
			st := newTestStore(t)
			state := chain.New("chain-1")
			p := New(state, ks, st, "did:agent-receipts-daemon:test")
			p.ParameterDisclosure = tc.enabled

			inputJSON := json.RawMessage(`{"path":"/tmp/file","mode":"r"}`)
			outputJSON := json.RawMessage(`{"bytes":42}`)
			body, err := json.Marshal(EmitterFrame{
				Version:   "1",
				TsEmit:    "2026-05-03T00:00:00Z",
				SessionID: "s",
				Channel:   "sdk",
				Tool:      EmitterTool{Name: "fs.read"},
				Input:     inputJSON,
				Output:    outputJSON,
				Decision:  "allowed",
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
			r := receipts[0]

			if r.CredentialSubject.Action.ParametersDisclosure != nil {
				t.Errorf("ParametersDisclosure must be nil regardless of flag (envelope wiring pending #280); got %#v", r.CredentialSubject.Action.ParametersDisclosure)
			}
			// Hashes are unaffected by the flag — they always commit to the raw
			// emitter payload.
			if r.CredentialSubject.Action.ParametersHash == "" {
				t.Error("parameters_hash must be present when input is set")
			}
			if r.CredentialSubject.Outcome.ResponseHash == "" {
				t.Error("response_hash must be present when output is set")
			}
		})
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
// the synthetic events_dropped receipt fails to persist, Process still returns
// nil and the live receipt is written. The synthetic failure is routed to
// ErrorLog rather than returned, keeping the return-value contract: a non-nil
// return from Process always means the live receipt was NOT persisted.
func TestProcess_DropCountSyntheticFailureLiveReceiptPersists(t *testing.T) {
	ks := newTestKeySource(t)
	underlying := newTestStore(t)
	// Fail only the first Insert (the synthetic receipt); the second (live) must succeed.
	st := &failOnNthInsert{ReceiptStore: underlying, n: 1}

	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	var logged string
	p.ErrorLog = func(format string, args ...any) {
		logged = fmt.Sprintf(format, args...)
	}

	if err := p.Process(dropFrame(t, 2)); err != nil {
		t.Errorf("Process returned error %v; want nil (live receipt was persisted)", err)
	}
	if logged == "" {
		t.Error("ErrorLog was not called; synthetic failure must be logged")
	}

	// Live receipt must be in the store.
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
		t.Errorf("seq = %d, want 1", got)
	}
}

// TestProcess_IssuerFieldsFromFrame verifies that IssuerName, IssuerModel, and
// OperatorID/OperatorName from the emitter frame are stamped onto the receipt
// Issuer, so proxy-supplied host identity flows through to every receipt.
func TestProcess_IssuerFieldsFromFrame(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:      "1",
		TsEmit:       "2026-05-03T00:00:00Z",
		SessionID:    "sess-abc",
		Channel:      "mcp",
		Tool:         EmitterTool{Name: "bash"},
		Decision:     "allowed",
		IssuerName:   "Claude Code",
		IssuerModel:  "claude-opus-4-5",
		OperatorID:   "did:web:anthropic.com",
		OperatorName: "Anthropic",
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
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	iss := receipts[0].Issuer
	if iss.Name != "Claude Code" {
		t.Errorf("Issuer.Name = %q, want %q", iss.Name, "Claude Code")
	}
	if iss.Model != "claude-opus-4-5" {
		t.Errorf("Issuer.Model = %q, want %q", iss.Model, "claude-opus-4-5")
	}
	if iss.Operator == nil {
		t.Fatal("Issuer.Operator is nil, want non-nil")
	}
	if iss.Operator.ID != "did:web:anthropic.com" {
		t.Errorf("Issuer.Operator.ID = %q, want %q", iss.Operator.ID, "did:web:anthropic.com")
	}
	if iss.Operator.Name != "Anthropic" {
		t.Errorf("Issuer.Operator.Name = %q, want %q", iss.Operator.Name, "Anthropic")
	}
	if iss.ID != "did:agent-receipts-daemon:test" {
		t.Errorf("Issuer.ID = %q; daemon ID must not be overwritten", iss.ID)
	}
	if iss.SessionID != "sess-abc" {
		t.Errorf("Issuer.SessionID = %q, want sess-abc", iss.SessionID)
	}
}

// TestProcess_EmptyOperatorFieldsLeaveOperatorNil verifies that when
// operator_id and operator_name are both absent from the frame, Issuer.Operator
// remains nil rather than being set to a zero-value struct.
func TestProcess_EmptyOperatorFieldsLeaveOperatorNil(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "noop"},
		Decision:  "allowed",
		// IssuerName set but no operator fields.
		IssuerName: "Some Host",
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
	if receipts[0].Issuer.Operator != nil {
		t.Errorf("Issuer.Operator = %+v; want nil when operator fields are absent", receipts[0].Issuer.Operator)
	}
	if receipts[0].Issuer.Name != "Some Host" {
		t.Errorf("Issuer.Name = %q, want \"Some Host\"", receipts[0].Issuer.Name)
	}
}

// TestValidateFrame_RejectsOversizedIdentityField verifies that validateFrame
// rejects frames where any identity field exceeds maxIdentityFieldLen bytes.
// The receipt store must remain empty after the rejection.
func TestValidateFrame_RejectsOversizedIdentityField(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:    "1",
		TsEmit:     "2026-05-03T00:00:00Z",
		SessionID:  "s",
		Channel:    "sdk",
		Tool:       EmitterTool{Name: "t"},
		Decision:   "allowed",
		IssuerName: strings.Repeat("a", 257),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = p.Process(socket.Frame{Payload: body})
	if err == nil {
		t.Fatal("expected error for oversized issuer_name, got nil")
	}
	if !strings.Contains(err.Error(), "issuer_name") {
		t.Errorf("error %q should mention \"issuer_name\"", err.Error())
	}
	if !strings.Contains(err.Error(), "256") {
		t.Errorf("error %q should mention the limit 256", err.Error())
	}

	// No receipt should have been stored.
	receipts, getErr := st.GetChain("chain-1")
	if getErr != nil {
		t.Fatalf("GetChain: %v", getErr)
	}
	if len(receipts) != 0 {
		t.Errorf("got %d receipts, want 0 (frame was rejected)", len(receipts))
	}
}

// TestValidateFrame_RejectsPartialOperator verifies that validateFrame rejects
// frames where operator_name is set without operator_id, preventing a receipt
// with an empty operator.id from being signed.
func TestValidateFrame_RejectsPartialOperator(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:      "1",
		TsEmit:       "2026-05-03T00:00:00Z",
		SessionID:    "s",
		Channel:      "sdk",
		Tool:         EmitterTool{Name: "t"},
		Decision:     "allowed",
		OperatorName: "Acme",
		// OperatorID intentionally absent.
	})
	if err != nil {
		t.Fatal(err)
	}
	err = p.Process(socket.Frame{Payload: body})
	if err == nil {
		t.Fatal("expected error for operator_name without operator_id, got nil")
	}
	if !strings.Contains(err.Error(), "operator_name") {
		t.Errorf("error %q should mention \"operator_name\"", err.Error())
	}

	// No receipt should have been stored.
	receipts, getErr := st.GetChain("chain-1")
	if getErr != nil {
		t.Fatalf("GetChain: %v", getErr)
	}
	if len(receipts) != 0 {
		t.Errorf("got %d receipts, want 0 (frame was rejected)", len(receipts))
	}
}
