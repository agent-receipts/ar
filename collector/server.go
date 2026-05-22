package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// Config holds collector server configuration.
type Config struct {
	// Addr is the listen address (e.g. ":8080"). Required.
	Addr string

	// MaxBodyBytes caps the size of a single receipt POST body. Bodies larger
	// than this are rejected with 400. Zero falls back to DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// ReadTimeout and WriteTimeout bound the HTTP server's I/O. Zero falls
	// back to sensible defaults.
	ReadTimeout, WriteTimeout time.Duration

	// Logger receives structured log records. Required.
	Logger *slog.Logger
}

// DefaultMaxBodyBytes is the request-body cap applied when Config.MaxBodyBytes
// is zero. 1 MiB is enough to cover signed receipts with HPKE-encrypted
// parameters_disclosure envelopes well beyond typical sizes while bounding
// memory exposure for adversarial clients.
const DefaultMaxBodyBytes int64 = 1 << 20

// NewServer wires the collector's routes onto a fresh http.Server. The caller
// is responsible for starting and shutting down the returned server.
func NewServer(cfg Config, store Store) (*http.Server, error) {
	if cfg.Addr == "" {
		return nil, errors.New("collector: Config.Addr is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("collector: Config.Logger is required")
	}
	if store == nil {
		return nil, errors.New("collector: Store is required")
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}

	mux := http.NewServeMux()
	mux.Handle("POST /receipts", &receiptHandler{
		store:        store,
		log:          cfg.Logger,
		maxBodyBytes: cfg.MaxBodyBytes,
	})
	mux.HandleFunc("GET /healthz", healthHandler(store, cfg.Logger))

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  pickDuration(cfg.ReadTimeout, 10*time.Second),
		WriteTimeout: pickDuration(cfg.WriteTimeout, 10*time.Second),
		IdleTimeout:  60 * time.Second,
	}
	return srv, nil
}

func pickDuration(v, fallback time.Duration) time.Duration {
	if v == 0 {
		return fallback
	}
	return v
}

// Handler exposes the collector's request multiplexer for testing without
// binding a listener.
func Handler(cfg Config, store Store) (http.Handler, error) {
	srv, err := NewServer(cfg, store)
	if err != nil {
		return nil, err
	}
	return srv.Handler, nil
}

type receiptHandler struct {
	store        Store
	log          *slog.Logger
	maxBodyBytes int64
}

// errorResponse is the wire body returned for non-201 responses. Mirrors the
// shape commonly used by JSON HTTP APIs (single `error` string) so client
// SDKs do not need a richer schema.
type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func (h *receiptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Cap body size before decoding. http.MaxBytesReader fails the JSON
	// decode with an http.MaxBytesError when the cap is exceeded.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)

	var ar receipt.AgentReceipt
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ar); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			h.log.Warn("receipt rejected: body too large", "limit", h.maxBodyBytes)
			writeError(w, http.StatusBadRequest, "request body exceeds maximum size")
			return
		}
		h.log.Warn("receipt rejected: malformed json", "err", err.Error())
		writeError(w, http.StatusBadRequest, "malformed receipt: "+err.Error())
		return
	}
	// Reject trailing data after the receipt. A second JSON value in the
	// body almost always indicates a client bug; better to surface it than
	// silently store the first one.
	if dec.More() {
		writeError(w, http.StatusBadRequest, "request body must contain exactly one JSON object")
		return
	}

	if err := validateReceiptStructure(ar); err != nil {
		h.log.Warn("receipt rejected: structural validation failed", "id", ar.ID, "err", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := receipt.HashReceipt(ar)
	if err != nil {
		// Canonicalisation failure here implies the receipt's JSON shape
		// passed Unmarshal but cannot be canonicalised. Treat as malformed.
		h.log.Warn("receipt rejected: canonicalization failed", "id", ar.ID, "err", err.Error())
		writeError(w, http.StatusBadRequest, "receipt canonicalization failed: "+err.Error())
		return
	}

	if err := h.store.Insert(ar, hash); err != nil {
		if errors.Is(err, ErrDuplicate) {
			h.log.Info("receipt already exists, returning 409", "id", ar.ID)
			writeJSON(w, http.StatusConflict, errorResponse{Error: "receipt id already exists"})
			return
		}
		h.log.Error("receipt insert failed", "id", ar.ID, "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	h.log.Info("receipt accepted",
		"id", ar.ID,
		"chain_id", ar.CredentialSubject.Chain.ChainID,
		"sequence", ar.CredentialSubject.Chain.Sequence,
	)
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":           ar.ID,
		"receipt_hash": hash,
	})
}

// validateReceiptStructure enforces the minimal shape required to make the
// store insert meaningful. The collector does not verify signatures (per
// ADR-0020) and does not validate semantic correctness — that is the
// auditor's job — but a receipt with no id, no chain, or no action is
// definitely malformed and the SDK should not retry it.
func validateReceiptStructure(r receipt.AgentReceipt) error {
	if r.ID == "" {
		return errors.New("receipt id is required")
	}
	if r.CredentialSubject.Chain.ChainID == "" {
		return errors.New("credentialSubject.chain.chain_id is required")
	}
	if r.CredentialSubject.Action.Type == "" {
		return errors.New("credentialSubject.action.type is required")
	}
	if r.Proof.ProofValue == "" {
		return errors.New("proof.proofValue is required (receipts must be signed before delivery)")
	}
	return nil
}

func healthHandler(store Store, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A simple Exists lookup against a known-missing id is enough to
		// confirm the backing store is responsive without mutating state.
		if _, err := store.Exists("__healthz__"); err != nil {
			log.Error("healthz: store unreachable", "err", err.Error())
			writeError(w, http.StatusServiceUnavailable, "store unreachable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// Run starts the server and blocks until ctx is cancelled, then gracefully
// shuts it down with the supplied drain timeout. Returns nil on a clean
// shutdown, or the first non-shutdown error encountered.
func Run(ctx context.Context, srv *http.Server, drainTimeout time.Duration, log *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		log.Info("collector listening", "addr", srv.Addr)
		err := srv.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("collector listen: %w", err)
		}
		return nil
	case <-ctx.Done():
		log.Info("collector shutting down", "drain_timeout", drainTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("collector shutdown: %w", err)
		}
		// Wait for ListenAndServe to return so a caller restarting the
		// server doesn't race against a still-bound socket.
		return <-errCh
	}
}
