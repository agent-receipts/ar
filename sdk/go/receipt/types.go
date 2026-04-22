// Package receipt provides types and functions for creating, signing, and
// verifying Action Receipts — W3C Verifiable Credentials for AI agent actions.
package receipt

import "encoding/json"

// Protocol constants (unexported to prevent mutation).
var (
	protocolContext        = []string{"https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"}
	protocolCredentialType = []string{"VerifiableCredential", "AgentReceipt"}
)

// Context returns a copy of the W3C VC context array.
func Context() []string { return append([]string{}, protocolContext...) }

// CredentialType returns a copy of the credential type array.
func CredentialType() []string { return append([]string{}, protocolCredentialType...) }

const Version = "0.2.0"

// RiskLevel classifies the security risk of an action.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// OutcomeStatus represents the result of an action.
type OutcomeStatus string

const (
	StatusSuccess OutcomeStatus = "success"
	StatusFailure OutcomeStatus = "failure"
	StatusPending OutcomeStatus = "pending"
)

// Operator identifies the AI model executing actions.
type Operator struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Issuer represents the agent that issued the receipt.
type Issuer struct {
	ID        string    `json:"id"`
	Type      string    `json:"type,omitempty"`
	Name      string    `json:"name,omitempty"`
	Operator  *Operator `json:"operator,omitempty"`
	Model     string    `json:"model,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
}

// Principal identifies the human or organisation that authorised the action.
type Principal struct {
	ID   string `json:"id"`
	Type string `json:"type,omitempty"`
}

// ActionTarget specifies the system and resource being acted upon.
type ActionTarget struct {
	System   string `json:"system"`
	Resource string `json:"resource,omitempty"`
}

// Action describes what the agent did.
type Action struct {
	ID               string        `json:"id"`
	Type             string        `json:"type"`
	ToolName         string        `json:"tool_name,omitempty"`
	RiskLevel        RiskLevel     `json:"risk_level"`
	Target           *ActionTarget `json:"target,omitempty"`
	ParametersHash   string        `json:"parameters_hash,omitempty"`
	Timestamp        string        `json:"timestamp"`
	TrustedTimestamp string        `json:"trusted_timestamp,omitempty"`
}

// Intent captures conversation context behind the action.
type Intent struct {
	ConversationHash       string `json:"conversation_hash,omitempty"`
	PromptPreview          string `json:"prompt_preview,omitempty"`
	PromptPreviewTruncated *bool  `json:"prompt_preview_truncated,omitempty"`
	ReasoningHash          string `json:"reasoning_hash,omitempty"`
}

// StateChange captures before/after state hashes.
type StateChange struct {
	BeforeHash string `json:"before_hash"`
	AfterHash  string `json:"after_hash"`
}

// Outcome describes the result of an action.
type Outcome struct {
	Status                OutcomeStatus `json:"status"`
	Error                 string        `json:"error,omitempty"`
	Reversible            *bool         `json:"reversible,omitempty"`
	ReversalMethod        string        `json:"reversal_method,omitempty"`
	ReversalWindowSeconds *int          `json:"reversal_window_seconds,omitempty"`
	StateChange           *StateChange  `json:"state_change,omitempty"`
	ResponseHash          string        `json:"response_hash,omitempty"`
}

// Authorization captures the scope and expiry of an action.
type Authorization struct {
	Scopes    []string `json:"scopes"`
	GrantedAt string   `json:"granted_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	GrantRef  string   `json:"grant_ref,omitempty"`
}

// Chain links receipts in a tamper-evident sequence.
type Chain struct {
	Sequence            int     `json:"sequence"`
	PreviousReceiptHash *string `json:"previous_receipt_hash"`
	ChainID             string  `json:"chain_id"`
	// Terminal, when non-nil and true, asserts this is the final receipt in
	// the chain. Spec §4.3.2 restricts the wire form to the constant true or
	// absent — explicit false is schema-invalid. MarshalJSON silently drops
	// Terminal when it is non-nil but false so external callers who set
	// Terminal: &falseVal still produce a valid JSON document.
	Terminal *bool `json:"terminal,omitempty"`
}

// MarshalJSON serializes Chain, silently omitting Terminal when it is set
// to false (spec §4.3.2 forbids `terminal: false` on the wire).
func (c Chain) MarshalJSON() ([]byte, error) {
	type chainAlias Chain
	a := chainAlias(c)
	if a.Terminal != nil && !*a.Terminal {
		a.Terminal = nil
	}
	return json.Marshal(a)
}

// CredentialSubject contains the core receipt payload.
type CredentialSubject struct {
	Principal     Principal      `json:"principal"`
	Action        Action         `json:"action"`
	Intent        *Intent        `json:"intent,omitempty"`
	Outcome       Outcome        `json:"outcome"`
	Authorization *Authorization `json:"authorization,omitempty"`
	Chain         Chain          `json:"chain"`
}

// Proof contains the Ed25519 signature.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
	ProofPurpose       string `json:"proofPurpose,omitempty"`
	ProofValue         string `json:"proofValue"`
}

// AgentReceipt is a signed W3C Verifiable Credential for an agent action.
type AgentReceipt struct {
	Context []string `json:"@context"`
	ID      string   `json:"id"`
	Type    []string `json:"type"`
	Version string   `json:"version"`
	Issuer  Issuer   `json:"issuer"`
	// issuanceDate follows W3C VC v1 naming; the protocol spec uses this
	// instead of VC v2's validFrom.
	IssuanceDate      string            `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
	Proof             Proof             `json:"proof"`
}

// UnsignedAgentReceipt is an AgentReceipt without a proof, ready to be signed.
type UnsignedAgentReceipt struct {
	Context           []string          `json:"@context"`
	ID                string            `json:"id"`
	Type              []string          `json:"type"`
	Version           string            `json:"version"`
	Issuer            Issuer            `json:"issuer"`
	IssuanceDate      string            `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

// KeyPair holds PEM-encoded Ed25519 keys.
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// TruncatePromptPreview truncates s to maxLen runes and sets the truncated flag.
func TruncatePromptPreview(s string, maxLen int) (preview string, truncated bool) {
	if maxLen <= 0 {
		return "", len(s) > 0
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s, false
	}
	return string(runes[:maxLen]), true
}
