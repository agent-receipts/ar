package receipt

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CreateInput holds the inputs for creating an unsigned receipt.
type CreateInput struct {
	Issuer        Issuer
	Principal     Principal
	Action        Action         // ID and Timestamp are auto-generated if empty.
	Outcome       Outcome
	Chain         Chain
	Intent        *Intent
	Authorization *Authorization
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
