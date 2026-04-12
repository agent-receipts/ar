/**
 * Agent Receipt schema types.
 *
 * These types model the Attest Agent Receipt as a W3C Verifiable Credential.
 * Both the full and minimal receipt variants share the same type — optional
 * fields are marked with `?`.
 */

export const CONTEXT = [
	"https://www.w3.org/ns/credentials/v2",
	"https://agentreceipts.ai/context/v1",
] as const;

export const CREDENTIAL_TYPE = [
	"VerifiableCredential",
	"AgentReceipt",
] as const;

export const VERSION = "0.1.0";

// --- Risk levels ---

export type RiskLevel = "low" | "medium" | "high" | "critical";

// --- Outcome status ---

export type OutcomeStatus = "success" | "failure" | "pending";

// --- Issuer ---

export interface Operator {
	id: string;
	name: string;
}

export interface Issuer {
	id: string;
	type?: string;
	name?: string;
	operator?: Operator;
	model?: string;
	session_id?: string;
}

// --- Principal ---

export interface Principal {
	id: string;
	type?: string;
}

// --- Action ---

export interface ActionTarget {
	system: string;
	resource?: string;
}

export interface Action {
	id: string;
	type: string;
	tool_name?: string;
	risk_level: RiskLevel;
	target?: ActionTarget;
	parameters_hash?: string;
	timestamp: string;
	trusted_timestamp?: string | null;
}

// --- Intent ---

export interface Intent {
	conversation_hash?: string;
	prompt_preview?: string;
	prompt_preview_truncated?: boolean;
	reasoning_hash?: string;
}

// --- Outcome ---

export interface StateChange {
	before_hash: string;
	after_hash: string;
}

export interface Outcome {
	status: OutcomeStatus;
	error?: string | null;
	reversible?: boolean;
	reversal_method?: string;
	reversal_window_seconds?: number;
	state_change?: StateChange;
}

// --- Authorization ---

export interface Authorization {
	scopes: string[];
	granted_at: string;
	expires_at?: string;
	grant_ref?: string | null;
}

// --- Chain ---

export interface Chain {
	sequence: number;
	previous_receipt_hash: string | null;
	chain_id: string;
}

// --- Credential Subject ---

export interface CredentialSubject {
	principal: Principal;
	action: Action;
	intent?: Intent;
	outcome: Outcome;
	authorization?: Authorization;
	chain: Chain;
}

// --- Proof ---

export interface Proof {
	type: string;
	created?: string;
	verificationMethod?: string;
	proofPurpose?: string;
	proofValue: string;
}

// --- Agent Receipt ---

export interface AgentReceipt {
	"@context": readonly string[];
	id: string;
	type: readonly string[];
	version: string;
	issuer: Issuer;
	issuanceDate: string;
	credentialSubject: CredentialSubject;
	proof: Proof;
}

/**
 * An Agent Receipt before signing — no proof field yet.
 */
export type UnsignedAgentReceipt = Omit<AgentReceipt, "proof">;
