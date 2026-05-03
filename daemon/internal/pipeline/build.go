// Package pipeline maps an emitter frame plus an OS-attested peer credential
// into a signed AgentReceipt and persists it to the store. The daemon's hot
// path runs through here.
package pipeline

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/chain"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

// multibaseBase64URL matches sdk/go/receipt/signing.go: receipts use base64url
// (multibase prefix "u") rather than the W3C default base58btc ("z").
const multibaseBase64URL = "u"

// SupportedFrameVersion is the only emitter-frame schema this daemon accepts.
// Bumping it requires a migration plan and a daemon-side translator for the
// old version; until that exists, accepting unknown versions would silently
// misinterpret future fields.
const SupportedFrameVersion = "1"

// EmitterFrame is the JSON payload emitters send. Mirrors ADR-0010 §"Schema
// split". Fields the emitter does not populate are zero/empty; the daemon
// fills in the authoritative chain/peer/id/ts_recv before signing.
//
// Phase 1 limitation: Input and Output are recognised in the schema (so the
// wire format already matches what Phase 2 emitters will send) but the daemon
// does not yet hash them into action.parameters_hash / outcome.response_hash.
// Accepting non-empty Input/Output today would silently drop the payload from
// the receipt and mislead emitter authors into thinking tool I/O is being
// committed when it isn't. validateFrame rejects frames that populate them
// until Phase 2 wires the canonical-hash path through receipt.Create's
// ResponseBody and an explicit ParametersHash computation.
type EmitterFrame struct {
	Version   string          `json:"v"`
	TsEmit    string          `json:"ts_emit"`
	SessionID string          `json:"session_id"`
	Channel   string          `json:"channel"`
	Tool      EmitterTool     `json:"tool"`
	Input     json.RawMessage `json:"input,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
	Error     string          `json:"error,omitempty"`
	Decision  string          `json:"decision"`
}

// EmitterTool identifies the tool the agent invoked.
type EmitterTool struct {
	Server string `json:"server,omitempty"`
	Name   string `json:"name"`
}

// Pipeline holds the daemon-owned dependencies (chain state, signer, store)
// shared across all incoming frames.
type Pipeline struct {
	State     *chain.State
	Keys      keysource.KeySource
	Store     store.ReceiptStore
	IssuerID  string // e.g. "did:agent-receipts-daemon:<host>"
	Now       func() time.Time
}

// New returns a Pipeline. Callers configure IssuerID; Now defaults to
// time.Now.UTC.
func New(s *chain.State, ks keysource.KeySource, store store.ReceiptStore, issuerID string) *Pipeline {
	return &Pipeline{
		State:    s,
		Keys:     ks,
		Store:    store,
		IssuerID: issuerID,
		Now:      func() time.Time { return time.Now().UTC() },
	}
}

// Process is the daemon's per-frame entrypoint. It parses the frame, allocates
// the next chain slot, builds and signs the AgentReceipt, persists it via
// store.Insert, and Commits the chain allocation. Any error before Commit
// triggers Rollback so the chain state is not advanced past a missing receipt.
func (p *Pipeline) Process(f socket.Frame) error {
	var frame EmitterFrame
	if err := json.Unmarshal(f.Payload, &frame); err != nil {
		return fmt.Errorf("decode emitter frame: %w", err)
	}
	if err := validateFrame(&frame); err != nil {
		return fmt.Errorf("invalid emitter frame: %w", err)
	}

	alloc := p.State.Allocate()
	signed, hash, err := p.buildAndSign(&frame, f.Peer, alloc)
	if err != nil {
		alloc.Rollback()
		return err
	}
	if err := p.Store.Insert(signed, hash); err != nil {
		alloc.Rollback()
		return fmt.Errorf("insert receipt: %w", err)
	}
	alloc.Commit(hash)
	return nil
}

func validateFrame(f *EmitterFrame) error {
	if f.Version == "" {
		return fmt.Errorf("missing v")
	}
	if f.Version != SupportedFrameVersion {
		return fmt.Errorf("unsupported frame version %q (this daemon accepts %q)", f.Version, SupportedFrameVersion)
	}
	if f.SessionID == "" {
		return fmt.Errorf("missing session_id")
	}
	if f.Channel == "" {
		return fmt.Errorf("missing channel")
	}
	if f.Tool.Name == "" {
		return fmt.Errorf("missing tool.name")
	}
	if f.Decision == "" {
		return fmt.Errorf("missing decision")
	}
	// Phase 1 hard-rejects Input/Output rather than silently dropping them —
	// see EmitterFrame doc comment.
	if len(f.Input) > 0 {
		return fmt.Errorf("input not supported in Phase 1 (would be silently dropped); see EmitterFrame doc")
	}
	if len(f.Output) > 0 {
		return fmt.Errorf("output not supported in Phase 1 (would be silently dropped); see EmitterFrame doc")
	}
	return nil
}

func (p *Pipeline) buildAndSign(
	f *EmitterFrame,
	peer socket.PeerCred,
	alloc chain.Allocation,
) (receipt.AgentReceipt, string, error) {
	now := p.Now().Format(time.RFC3339)

	// Map decision -> outcome.
	var status receipt.OutcomeStatus
	switch f.Decision {
	case "allowed":
		status = receipt.StatusSuccess
	case "denied":
		status = receipt.StatusFailure
	case "pending":
		status = receipt.StatusPending
	default:
		return receipt.AgentReceipt{}, "", fmt.Errorf("unknown decision %q", f.Decision)
	}

	actionType := f.Channel + "." + f.Tool.Name
	if f.Tool.Server != "" {
		actionType = f.Channel + "." + f.Tool.Server + "." + f.Tool.Name
	}

	// Phase 1 stashes peer attestation in Action.ParametersDisclosure as a
	// placeholder. ADR-0010 calls for a dedicated `peer` field on the receipt;
	// adding that requires a spec change (out of scope per AGENTS.md "Never
	// modify the protocol spec without explicit human approval"). Tracked as a
	// follow-up for the emitter-refactor phase.
	disclosure := map[string]string{
		"peer.platform":  peer.Platform,
		"peer.pid":       strconv.FormatInt(int64(peer.PID), 10),
		"peer.uid":       strconv.FormatInt(int64(peer.UID), 10),
		"peer.gid":       strconv.FormatInt(int64(peer.GID), 10),
		"peer.exe_path":  peer.ExePath,
		"channel":        f.Channel,
		"session_id":     f.SessionID,
		"ts_emit":        f.TsEmit,
		"ts_recv":        now,
	}
	if f.Error != "" {
		disclosure["error"] = f.Error
	}

	unsigned := receipt.Create(receipt.CreateInput{
		Issuer: receipt.Issuer{
			ID:        p.IssuerID,
			Type:      "AgentReceiptsDaemon",
			SessionID: f.SessionID,
		},
		Principal: receipt.Principal{ID: "did:user:unknown"},
		Action: receipt.Action{
			Type:                 actionType,
			ToolName:             f.Tool.Name,
			RiskLevel:            receipt.RiskLow,
			Timestamp:            now,
			ParametersDisclosure: disclosure,
		},
		Outcome: receipt.Outcome{
			Status: status,
			Error:  f.Error,
		},
		Chain: receipt.Chain{
			Sequence:            int(alloc.Sequence),
			PreviousReceiptHash: alloc.PrevHash,
			ChainID:             p.State.ChainID(),
		},
	})
	// receipt.Create stamps IssuanceDate from time.Now() internally. Replace it
	// with our deterministic now so action.timestamp, issuanceDate, and
	// proof.created all share a single value (and tests can override Now).
	unsigned.IssuanceDate = now

	canonical, err := receipt.Canonicalize(unsigned)
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("canonicalize: %w", err)
	}
	sig, err := p.Keys.Sign([]byte(canonical))
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("sign: %w", err)
	}

	signed := receipt.AgentReceipt{
		Context:           unsigned.Context,
		ID:                unsigned.ID,
		Type:              unsigned.Type,
		Version:           unsigned.Version,
		Issuer:            unsigned.Issuer,
		IssuanceDate:      unsigned.IssuanceDate,
		CredentialSubject: unsigned.CredentialSubject,
		Proof: receipt.Proof{
			Type:               "Ed25519Signature2020",
			Created:            now,
			VerificationMethod: p.Keys.VerificationMethod(),
			ProofPurpose:       "assertionMethod",
			ProofValue:         multibaseBase64URL + base64.RawURLEncoding.EncodeToString(sig),
		},
	}

	hash, err := receipt.HashReceipt(signed)
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("hash receipt: %w", err)
	}
	return signed, hash, nil
}
