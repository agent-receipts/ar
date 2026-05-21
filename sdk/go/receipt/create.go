package receipt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CreateInput holds the inputs for creating an unsigned receipt.
type CreateInput struct {
	Issuer        Issuer
	Principal     Principal
	Action        Action // ID and Timestamp are auto-generated if empty.
	Outcome       Outcome
	Chain         Chain
	Intent        *Intent
	Authorization *Authorization
	// ResponseBody is the pre-redacted response body to hash. When non-empty,
	// the hash is computed (redact → hash → sign ordering) and stored in
	// outcome.ResponseHash. Callers must redact before passing.
	ResponseBody json.RawMessage

	// Terminal marks this as the final receipt in the chain.
	// When true, sets chain.terminal: true. Never emits false.
	Terminal bool

	// TerminationStatus, when non-empty and Terminal is true, sets
	// chain.status on the receipt. MUST be StatusComplete or StatusInterrupted
	// (spec §7.3.3). Setting TerminationStatus without Terminal is ignored —
	// the spec requires status to coexist with terminal.
	TerminationStatus string
}

// Create builds an unsigned AgentReceipt from structured inputs.
// It auto-generates the receipt ID, action ID, issuance date, and action
// timestamp (if not already set in Action).
func Create(input CreateInput) UnsignedAgentReceipt {
	now := time.Now().UTC().Format(time.RFC3339)

	action := input.Action
	if action.ID == "" {
		action.ID = fmt.Sprintf("act_%s", uuid.New().String())
	}
	if action.Timestamp == "" {
		action.Timestamp = now
	}

	subject := CredentialSubject{
		Principal:     input.Principal,
		Action:        action,
		Outcome:       input.Outcome,
		Chain:         input.Chain,
		Intent:        input.Intent,
		Authorization: input.Authorization,
	}

	// Compute response_hash when a response body is supplied.
	// Panic on unmarshal/canonicalization failure: passing non-JSON as ResponseBody
	// is a programming error — silently omitting the hash would undermine the
	// security property the caller intended to commit to.
	if len(input.ResponseBody) > 0 {
		var responseAny any
		if err := json.Unmarshal(input.ResponseBody, &responseAny); err != nil {
			panic(fmt.Sprintf("receipt.Create: ResponseBody is not valid JSON: %v", err))
		}
		canonical, err := Canonicalize(responseAny)
		if err != nil {
			panic(fmt.Sprintf("receipt.Create: ResponseBody canonicalization failed: %v", err))
		}
		subject.Outcome.ResponseHash = SHA256Hash(canonical)
	}

	// Set terminal marker when requested (never set false).
	if input.Terminal {
		t := true
		subject.Chain.Terminal = &t
		// Status is only emitted alongside terminal (spec §7.3.3).
		if input.TerminationStatus != "" {
			subject.Chain.Status = input.TerminationStatus
		}
	}

	return UnsignedAgentReceipt{
		Context:           Context(),
		ID:                fmt.Sprintf("urn:receipt:%s", uuid.New().String()),
		Type:              CredentialType(),
		Version:           Version,
		Issuer:            input.Issuer,
		IssuanceDate:      now,
		CredentialSubject: subject,
	}
}
