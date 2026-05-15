// Package pipeline maps an emitter frame plus an OS-attested peer credential
// into a signed AgentReceipt and persists it to the store. The daemon's hot
// path runs through here.
package pipeline

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/chain"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
	"github.com/agent-receipts/ar/sdk/go/taxonomy"
)

// multibaseBase64URL matches sdk/go/receipt/signing.go: receipts use base64url
// (multibase prefix "u") rather than the W3C default base58btc ("z").
const multibaseBase64URL = "u"

// SupportedFrameVersion is the only emitter-frame schema this daemon accepts.
// Bumping it requires a migration plan and a daemon-side translator for the
// old version; until that exists, accepting unknown versions would silently
// misinterpret future fields.
const SupportedFrameVersion = "1"

// actionTypeEventsDropped is the action type for the daemon-synthesised
// events_dropped receipt. The "agent_receipts" namespace identifies the daemon
// as the source rather than a user-facing tool channel.
const actionTypeEventsDropped = "agent_receipts.events_dropped"

// EmitterFrame is the JSON payload emitters send. Mirrors ADR-0010 §"Schema
// split". Fields the emitter does not populate are zero/empty; the daemon
// fills in the authoritative chain/peer/id/ts_recv before signing.
//
// Input and Output carry the raw tool I/O. The daemon does NOT persist the
// raw bytes in the receipt; it canonicalises them (RFC 8785) and stores only
// the SHA-256 digests in action.parameters_hash and outcome.response_hash.
// A literal JSON null (or omitted field) means "no payload" and produces no
// hash — hashing the literal "null" would falsely commit the daemon to a
// value the emitter did not send.
//
// DropCount, when > 0, records events the emitter dropped (connect/write
// failures) before this successful send. The daemon inserts a synthetic
// events_dropped receipt with this count before the live receipt so the gap
// is visible in the chain.
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
	DropCount int64           `json:"drop_count,omitempty"`
}

// EmitterTool identifies the tool the agent invoked.
type EmitterTool struct {
	Server string `json:"server,omitempty"`
	Name   string `json:"name"`
}

// Pipeline holds the daemon-owned dependencies (chain state, signer, store)
// shared across all incoming frames.
type Pipeline struct {
	State    *chain.State
	Keys     keysource.KeySource
	Store    store.ReceiptStore
	IssuerID string // e.g. "did:agent-receipts-daemon:<host>"
	Now      func() time.Time
	TraceLog io.Writer // Optional trace log for testing; nil = silent

	// traceMu serialises writes to TraceLog. Process is invoked concurrently
	// from the listener accept loop, so unguarded fmt.Fprintf calls would
	// interleave bytes from different frames in the buffer (and race the
	// underlying io.Writer state). The mutex is independent of State's
	// chain-allocation lock, so tracing doesn't contend with sequence
	// allocation; however it does block the processing of that frame.
	traceMu sync.Mutex
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
		TraceLog: nil,
	}
}

// Process is the daemon's per-frame entrypoint. It parses the frame, allocates
// the next chain slot, builds and signs the AgentReceipt, persists it via
// store.Insert, and Commits the chain allocation. Any error before Commit
// triggers Rollback so the chain state is not advanced past a missing receipt.
//
// When the frame carries a positive DropCount, Process first inserts a
// synthetic events_dropped receipt (in its own allocation) that makes the gap
// visible in the chain before the live receipt.
//
// Rollback is deferred — and chain.Allocation.Commit/Rollback are idempotent
// via sync.Once — so the chain mutex is released even if buildAndSign or
// Store.Insert panics. Without that guarantee, a single panicking frame would
// orphan the lock and deadlock the daemon for every subsequent emitter on the
// same socket.
func (p *Pipeline) Process(f socket.Frame) error {
	var frame EmitterFrame
	if err := json.Unmarshal(f.Payload, &frame); err != nil {
		return fmt.Errorf("decode emitter frame: %w", err)
	}
	if err := validateFrame(&frame); err != nil {
		return fmt.Errorf("invalid emitter frame: %w", err)
	}

	p.trace("frame received: session=%s channel=%s tool=%s drop_count=%d",
		frame.SessionID, frame.Channel, frame.Tool.Name, frame.DropCount)

	if frame.DropCount > 0 {
		if err := p.insertDropReceipt(&frame, f.Peer); err != nil {
			return fmt.Errorf("insert events_dropped receipt: %w", err)
		}
	}

	alloc := p.State.Allocate()
	defer alloc.Rollback()

	signed, hash, err := p.buildAndSign(&frame, f.Peer, alloc)
	if err != nil {
		return err
	}
	p.trace("receipt signed: seq=%d hash=%s", alloc.Sequence, hash)

	if err := p.Store.Insert(signed, hash); err != nil {
		return fmt.Errorf("insert receipt: %w", err)
	}
	p.trace("receipt stored: seq=%d", alloc.Sequence)

	alloc.Commit(hash)
	return nil
}

// insertDropReceipt allocates a chain slot, builds a synthetic events_dropped
// receipt encoding the emitter's drop count, and commits. Called by Process
// before the live receipt when frame.DropCount > 0.
func (p *Pipeline) insertDropReceipt(frame *EmitterFrame, peer socket.PeerCred) error {
	alloc := p.State.Allocate()
	defer alloc.Rollback()

	p.trace("events_dropped receipt: session=%s drop_count=%d seq=%d",
		frame.SessionID, frame.DropCount, alloc.Sequence)

	signed, hash, err := p.buildAndSignDropReceipt(frame.DropCount, frame.SessionID, peer, alloc)
	if err != nil {
		return err
	}

	if err := p.Store.Insert(signed, hash); err != nil {
		return fmt.Errorf("insert drop receipt: %w", err)
	}

	alloc.Commit(hash)
	return nil
}

// trace writes a trace line to TraceLog if it's not nil. Safe to call
// concurrently — see Pipeline.traceMu.
func (p *Pipeline) trace(format string, args ...interface{}) {
	if p.TraceLog == nil {
		return
	}
	p.traceMu.Lock()
	defer p.traceMu.Unlock()
	fmt.Fprintf(p.TraceLog, format+"\n", args...)
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
	// ts_emit is part of the documented Phase 1 wire schema. The daemon
	// doesn't trust it for the receipt timestamp (action.timestamp,
	// issuanceDate, proof.created all come from p.Now()), but requiring a
	// well-formed value pins the emitter contract — silently accepting
	// "" or junk text would let a buggy emitter ship without anyone
	// noticing. RFC3339[Nano] match the format the README documents.
	if f.TsEmit == "" {
		return fmt.Errorf("missing ts_emit")
	}
	if _, err := time.Parse(time.RFC3339Nano, f.TsEmit); err != nil {
		// time.RFC3339Nano accepts both RFC3339 and the nanosecond extension.
		return fmt.Errorf("ts_emit %q is not RFC3339/RFC3339Nano: %w", f.TsEmit, err)
	}
	if f.Channel == "" {
		return fmt.Errorf("missing channel")
	}
	if f.Tool.Name == "" {
		return fmt.Errorf("missing tool.name")
	}
	switch f.Decision {
	case "":
		return fmt.Errorf("missing decision")
	case "allowed", "denied", "pending":
		// ok
	default:
		return fmt.Errorf("unknown decision %q (want allowed|denied|pending)", f.Decision)
	}
	if f.DropCount < 0 {
		return fmt.Errorf("drop_count %d is negative", f.DropCount)
	}
	// Input and Output are accepted as any valid JSON value (object, array,
	// primitive, or null). json.Unmarshal into EmitterFrame already validated
	// JSON syntax, so anything reaching this point is well-formed. The hash
	// computation happens in buildAndSign; null/empty are skipped there.
	return nil
}

// hasJSONPayload reports whether raw is a JSON value other than null.
// Whitespace and the literal "null" both count as no-payload.
func hasJSONPayload(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	return !bytes.Equal(trimmed, []byte("null"))
}

// canonicalSHA256 canonicalises raw per RFC 8785 and returns the
// "sha256:<hex>" digest. Callers MUST check hasJSONPayload first: a literal
// JSON null reaches receipt.Canonicalize and hashes "null", which would
// falsely commit the daemon to a value the emitter did not send.
//
// raw is passed to receipt.Canonicalize directly; json.RawMessage's
// MarshalJSON returns its bytes verbatim, so Canonicalize's existing
// marshal+unmarshal handles the parse without us doing an extra unmarshal
// here. (Empty RawMessage is not a callable shape — Canonicalize would
// return EOF — but hasJSONPayload rejects it before we get here.)
//
// Errors are real and expected: a JSON number like `1e400` is syntactically
// valid (so it survives EmitterFrame's outer Unmarshal as a token) but
// overflows float64 when Canonicalize re-parses into Go's `any`. The daemon
// MUST surface that as a per-frame error and keep running; a panic here
// would let any authenticated emitter DoS the daemon — and the orphaned
// chain.State allocation, even with the deferred-Rollback guard in Process,
// would still mean Process never returns to the listener loop for the bad
// frame.
func canonicalSHA256(raw json.RawMessage) (string, error) {
	canonical, err := receipt.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	return receipt.SHA256Hash(canonical), nil
}

func (p *Pipeline) buildAndSign(
	f *EmitterFrame,
	peer socket.PeerCred,
	alloc chain.Allocation,
) (receipt.AgentReceipt, string, error) {
	now := p.Now().Format(time.RFC3339)

	// receipt.Chain.Sequence is `int`, which is 32-bit on 32-bit platforms.
	// Refuse rather than silently overflow into a negative or wrapped value
	// that would corrupt chain verification downstream.
	if alloc.Sequence > int64(math.MaxInt) {
		return receipt.AgentReceipt{}, "", fmt.Errorf("chain sequence %d exceeds int range on this platform (max %d)", alloc.Sequence, math.MaxInt)
	}

	// validateFrame already restricted f.Decision to the supported set, so the
	// switch never falls through.
	// A non-empty error field means the tool call ran but the upstream returned
	// an error; even though the proxy permitted the call (decision="allowed"),
	// the execution outcome is a failure.
	var status receipt.OutcomeStatus
	switch f.Decision {
	case "allowed":
		if f.Error != "" {
			status = receipt.StatusFailure
		} else {
			status = receipt.StatusSuccess
		}
	case "denied":
		status = receipt.StatusFailure
	case "pending":
		status = receipt.StatusPending
	}

	actionType := f.Channel + "." + f.Tool.Name
	if f.Tool.Server != "" {
		actionType = f.Channel + "." + f.Tool.Server + "." + f.Tool.Name
	}

	// Phase 1 stashes the OS-attested peer cred in Action.ParametersDisclosure
	// as a placeholder. ADR-0010 calls for a dedicated `peer` field on the
	// receipt; adding that requires a spec change (out of scope per AGENTS.md
	// "Never modify the protocol spec without explicit human approval"), so
	// peer.* keys ride on the existing field until Phase 2.
	//
	// NOTE: parameters_disclosure is operator-allowlisted additive metadata in
	// the spec. Until a top-level peer field exists, this map MUST stay
	// minimal: only OS-attested fields the daemon vouches for. Emitter-
	// supplied content (channel, session_id, ts_emit, error) lives elsewhere
	// on the receipt — channel is folded into action.type, session_id into
	// issuer.session_id, error into outcome.error. The emitter-asserted
	// ts_emit is dropped (it is untrusted self-report and would not add audit
	// value); the daemon's authoritative receive-time is the `now` value
	// already stamped into action.timestamp, issuanceDate, and proof.created.
	// Mirroring any of these into parameters_disclosure could accidentally
	// persist PII pulled from emitter-controlled bytes, so we don't.
	disclosure := map[string]string{
		"peer.platform": peer.Platform,
		"peer.pid":      strconv.FormatInt(int64(peer.PID), 10),
		// uid_t / gid_t are unsigned 32-bit; format as unsigned to avoid wrap.
		"peer.uid":      strconv.FormatUint(uint64(peer.UID), 10),
		"peer.gid":      strconv.FormatUint(uint64(peer.GID), 10),
		"peer.exe_path": peer.ExePath,
	}

	// Risk derives from the taxonomy. Daemon-constructed action types like
	// "mcp_proxy.github.list_repos" do not match any built-in entry, so
	// ResolveActionType falls back to UnknownAction (RiskMedium). That's the
	// safer default than always emitting RiskLow — Phase 2 emitters that
	// know the taxonomic action type can override it via the action.type
	// field once the emitter SDKs land.
	risk := taxonomy.ResolveActionType(actionType).RiskLevel

	action := receipt.Action{
		Type:                 actionType,
		ToolName:             f.Tool.Name,
		RiskLevel:            risk,
		Timestamp:            now,
		ParametersDisclosure: disclosure,
	}
	if hasJSONPayload(f.Input) {
		hash, err := canonicalSHA256(f.Input)
		if err != nil {
			return receipt.AgentReceipt{}, "", fmt.Errorf("hash input: %w", err)
		}
		action.ParametersHash = hash
	}

	outcome := receipt.Outcome{
		Status: status,
		Error:  f.Error,
	}
	if hasJSONPayload(f.Output) {
		// Hash Output here rather than via receipt.CreateInput.ResponseBody
		// (which panics on bad JSON). f.Output is emitter-controlled and may
		// be syntactically valid JSON yet still fail re-unmarshal — see
		// canonicalSHA256 doc — so the daemon MUST surface that as an error,
		// not a crash.
		hash, err := canonicalSHA256(f.Output)
		if err != nil {
			return receipt.AgentReceipt{}, "", fmt.Errorf("hash output: %w", err)
		}
		outcome.ResponseHash = hash
	}

	return p.signAndHash(receipt.CreateInput{
		Issuer: receipt.Issuer{
			ID:        p.IssuerID,
			Type:      "AgentReceiptsDaemon",
			SessionID: f.SessionID,
		},
		Principal: receipt.Principal{ID: "did:user:unknown"},
		Action:    action,
		Outcome:   outcome,
		Chain: receipt.Chain{
			Sequence:            int(alloc.Sequence),
			PreviousReceiptHash: alloc.PrevHash,
			ChainID:             p.State.ChainID(),
		},
	}, now)
}

// buildAndSignDropReceipt constructs a synthetic events_dropped receipt that
// records the emitter's accumulated drop count in the chain. Called by
// insertDropReceipt when frame.DropCount > 0.
func (p *Pipeline) buildAndSignDropReceipt(
	dropCount int64,
	sessionID string,
	peer socket.PeerCred,
	alloc chain.Allocation,
) (receipt.AgentReceipt, string, error) {
	now := p.Now().Format(time.RFC3339)

	if alloc.Sequence > int64(math.MaxInt) {
		return receipt.AgentReceipt{}, "", fmt.Errorf("chain sequence %d exceeds int range on this platform (max %d)", alloc.Sequence, math.MaxInt)
	}

	return p.signAndHash(receipt.CreateInput{
		Issuer: receipt.Issuer{
			ID:        p.IssuerID,
			Type:      "AgentReceiptsDaemon",
			SessionID: sessionID,
		},
		Principal: receipt.Principal{ID: "did:user:unknown"},
		Action: receipt.Action{
			Type:      actionTypeEventsDropped,
			ToolName:  "events_dropped",
			RiskLevel: receipt.RiskLow,
			Timestamp: now,
			ParametersDisclosure: map[string]string{
				"drop_count":    strconv.FormatInt(dropCount, 10),
				"peer.platform": peer.Platform,
				"peer.pid":      strconv.FormatInt(int64(peer.PID), 10),
				"peer.uid":      strconv.FormatUint(uint64(peer.UID), 10),
				"peer.gid":      strconv.FormatUint(uint64(peer.GID), 10),
				"peer.exe_path": peer.ExePath,
			},
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain: receipt.Chain{
			Sequence:            int(alloc.Sequence),
			PreviousReceiptHash: alloc.PrevHash,
			ChainID:             p.State.ChainID(),
		},
	}, now)
}

// signAndHash builds, signs, and hashes one receipt. It is the common tail
// shared by buildAndSign and buildAndSignDropReceipt — both construct a
// CreateInput, set the issuance timestamp, and then need identical
// canonicalize → sign → hash steps.
func (p *Pipeline) signAndHash(in receipt.CreateInput, now string) (receipt.AgentReceipt, string, error) {
	unsigned := receipt.Create(in)
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
