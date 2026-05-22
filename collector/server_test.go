package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func newTestHandler(t *testing.T) (http.Handler, *InMemoryStore) {
	t.Helper()
	store := NewInMemoryStore()
	h, err := Handler(Config{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return h, store
}

// signedTestReceipt produces a receipt whose JSON shape passes the
// collector's structural validator. The proof value is a placeholder — the
// collector does not verify signatures (per ADR-0020).
func signedTestReceipt(id string) receipt.AgentReceipt {
	r := testReceipt(id)
	r.Proof = receipt.Proof{
		Type:       "Ed25519Signature2020",
		ProofValue: "u-placeholder",
	}
	return r
}

func postReceipt(t *testing.T, h http.Handler, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	switch v := body.(type) {
	case string:
		buf.WriteString(v)
	case []byte:
		buf.Write(v)
	default:
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/receipts", &buf)
	req.Header.Set("Content-Type", "application/ld+json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServer_PostReceipt_201(t *testing.T) {
	h, store := newTestHandler(t)
	r := signedTestReceipt("urn:receipt:srv:1")

	rec := postReceipt(t, h, r)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID          string `json:"id"`
		ReceiptHash string `json:"receipt_hash"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode 201 body: %v", err)
	}
	if resp.ID != r.ID {
		t.Fatalf("response id = %q, want %q", resp.ID, r.ID)
	}
	if !strings.HasPrefix(resp.ReceiptHash, "sha256:") {
		t.Fatalf("response receipt_hash = %q, want sha256: prefix", resp.ReceiptHash)
	}

	stored, hash, ok := store.Get(r.ID)
	if !ok {
		t.Fatalf("receipt not present in store after 201")
	}
	if stored.ID != r.ID {
		t.Fatalf("stored.ID = %q, want %q", stored.ID, r.ID)
	}
	if hash != resp.ReceiptHash {
		t.Fatalf("stored hash %q != response hash %q", hash, resp.ReceiptHash)
	}
}

func TestServer_PostReceipt_409Duplicate(t *testing.T) {
	h, _ := newTestHandler(t)
	r := signedTestReceipt("urn:receipt:srv:dup")

	if rec := postReceipt(t, h, r); rec.Code != http.StatusCreated {
		t.Fatalf("first post status = %d, want 201", rec.Code)
	}
	rec := postReceipt(t, h, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate post status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
}

func TestServer_PostReceipt_400MalformedJSON(t *testing.T) {
	h, store := newTestHandler(t)
	rec := postReceipt(t, h, "{not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if store.Len() != 0 {
		t.Fatalf("store mutated on 400: %d entries", store.Len())
	}
}

func TestServer_PostReceipt_400MissingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*receipt.AgentReceipt)
		want   string
	}{
		{"empty id", func(r *receipt.AgentReceipt) { r.ID = "" }, "receipt id is required"},
		{"empty chain_id", func(r *receipt.AgentReceipt) { r.CredentialSubject.Chain.ChainID = "" }, "chain_id"},
		{"empty action.type", func(r *receipt.AgentReceipt) { r.CredentialSubject.Action.Type = "" }, "action.type"},
		{"empty proof", func(r *receipt.AgentReceipt) { r.Proof = receipt.Proof{} }, "proof.proofValue"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, store := newTestHandler(t)
			r := signedTestReceipt("urn:receipt:srv:missing-" + tc.name)
			tc.mutate(&r)
			rec := postReceipt(t, h, r)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("response body %q does not mention %q", rec.Body.String(), tc.want)
			}
			if store.Len() != 0 {
				t.Fatalf("store mutated on 400: %d entries", store.Len())
			}
		})
	}
}

func TestServer_PostReceipt_400BodyTooLarge(t *testing.T) {
	store := NewInMemoryStore()
	h, err := Handler(Config{
		Addr:         ":0",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBodyBytes: 64,
	}, store)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	r := signedTestReceipt("urn:receipt:srv:big")
	rec := postReceipt(t, h, r) // serialised form is well over 64 bytes
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if store.Len() != 0 {
		t.Fatalf("store mutated on oversized body: %d entries", store.Len())
	}
}

func TestServer_PostReceipt_405WrongMethod(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestServer_PostReceipt_500StoreError(t *testing.T) {
	failing := &failingStore{err: errors.New("disk fire")}
	h, err := Handler(Config{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, failing)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := postReceipt(t, h, signedTestReceipt("urn:receipt:srv:fail"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
	}
}

func TestServer_Healthz_OK(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestServer_Healthz_StoreUnreachable(t *testing.T) {
	failing := &failingStore{err: errors.New("disk fire")}
	h, err := Handler(Config{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, failing)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestServer_Run_GracefulShutdown(t *testing.T) {
	// Bind on an OS-assigned port via httptest.NewUnstartedServer to avoid
	// race conditions with the real Run goroutine. We exercise Run's shutdown
	// path directly by starting Run in a goroutine and cancelling its ctx.
	store := NewInMemoryStore()
	srv, err := NewServer(Config{
		Addr:   "127.0.0.1:0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Bind a TCP listener on an OS-assigned port and Serve directly on it.
	// Using ListenAndServe would race the test against the server's own
	// listener setup; an explicit listener lets us be sure the server is
	// reachable before issuing the shutdown.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv.Addr = ln.Addr().String()

	runErr := make(chan error, 1)
	go func() {
		// Use Serve directly so we control the listener; mirrors what
		// production main wires up modulo signal handling.
		serveErr := srv.Serve(ln)
		if !errors.Is(serveErr, http.ErrServerClosed) {
			runErr <- serveErr
			return
		}
		runErr <- nil
	}()

	// Sanity-check the server is up and accepts requests.
	resp, err := http.Get("http://" + srv.Addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz before shutdown: %v", err)
	}
	resp.Body.Close()

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Serve returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s of Shutdown")
	}
}

// failingStore is a Store that returns its err from every method. Used to
// exercise the 500 / 503 paths without contorting the in-memory impl.
type failingStore struct{ err error }

func (s *failingStore) Insert(_ receipt.AgentReceipt, _ string) error { return s.err }
func (s *failingStore) Exists(_ string) (bool, error)                 { return false, s.err }
func (s *failingStore) Close() error                                  { return nil }
