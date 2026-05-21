/**
 * Agent Receipt schema types.
 *
 * These types model the Agent Receipt as a W3C Verifiable Credential.
 * Both the full and minimal receipt variants share the same type — optional
 * fields are marked with `?`.
 */

import type { DisclosureEnvelope } from "./disclosure.js";

export const CONTEXT = [
	"https://www.w3.org/ns/credentials/v2",
	"https://agentreceipts.ai/context/v1",
] as const;

export const CREDENTIAL_TYPE = [
	"VerifiableCredential",
	"AgentReceipt",
] as const;

export const VERSION = "0.2.0";

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

/**
 * OS-attested peer process metadata captured by the daemon at the SDK↔daemon
 * boundary. Present only on receipts emitted through a daemon (ADR-0010);
 * absent on direct SDK emissions. Daemon-attested, not agent-claimed.
 *
 * `pid` is a JS `number` because TS/JSON has no fixed-width integer type; the
 * spec describes it as POSIX `pid_t` (32-bit signed). `uid` and `gid` are
 * POSIX-only and absent on platforms where they do not apply (e.g. Windows).
 * `exe_path` is best-effort and may be absent in locked-down sandboxes or
 * when /proc is unavailable.
 */
export interface PeerCredential {
	/** OS platform identifier (e.g. "darwin", "linux", "windows"). */
	platform: string;
	/** Peer process ID. POSIX pid_t width (32-bit signed integer). */
	pid: number;
	/** Peer process effective UID. POSIX-only; omit on Windows. */
	uid?: number;
	/** Peer process effective GID. POSIX-only; omit on Windows. */
	gid?: number;
	/** Best-effort absolute path of the peer process executable. */
	exe_path?: string;
}

/**
 * Daemon-observed emitter-side metadata. Currently used for synthetic
 * events_dropped receipts (ADR-0010). Daemon-attested, not agent-claimed.
 */
export interface EmitterMetadata {
	/** Count of audit events the emitter dropped from its in-process buffer
	 *  before flushing to the daemon. */
	drop_count?: number;
}

export interface Action {
	id: string;
	type: string;
	tool_name?: string;
	risk_level: RiskLevel;
	target?: ActionTarget;
	parameters_hash?: string;
	/**
	 * HPKE asymmetric encryption envelope of the action parameters
	 * (ADR-0012 amendment 2026-05-18; spec v0.3.0).
	 *
	 * The signed receipt commits to the ciphertext; only the holder of the
	 * forensic X25519 private key can recover the plaintext. Build with
	 * {@link encryptDisclosure} from `./disclosure.js`.
	 *
	 * `parameters_hash` remains the cryptographic commitment to the full
	 * payload and is always authoritative; this field is additive metadata.
	 *
	 * Pre-1.0 the spec's `oneOf` still admits the legacy flat-map shape
	 * (v0.2.0 / v0.2.1) for verifier compatibility, but the TS SDK only
	 * emits the envelope shape going forward. Verifiers that need to ingest
	 * legacy receipts must use schema validation rather than this type.
	 */
	parameters_disclosure?: DisclosureEnvelope;
	/**
	 * OS-attested peer process metadata captured by the daemon (ADR-0010).
	 * Absent on direct SDK emissions; only present when a daemon attests
	 * the SDK↔daemon boundary.
	 */
	peer_credential?: PeerCredential;
	/**
	 * Daemon-observed emitter-side metadata (ADR-0010). Currently carries
	 * `drop_count` for synthetic events_dropped receipts.
	 */
	emitter_metadata?: EmitterMetadata;
	timestamp: string;
	trusted_timestamp?: string;
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
	error?: string;
	reversible?: boolean;
	reversal_method?: string;
	reversal_window_seconds?: number;
	state_change?: StateChange;
	/** SHA-256 hash of the RFC 8785 canonical JSON of the server's response,
	 *  computed after secret redaction (redact → hash → sign). */
	response_hash?: string;
}

// --- Authorization ---

export interface Authorization {
	scopes: string[];
	granted_at: string;
	expires_at?: string;
	grant_ref?: string;
}

// --- Chain ---

export interface Chain {
	sequence: number;
	previous_receipt_hash: string | null;
	chain_id: string;
	/** When present, MUST be true. Marks this as the final receipt in the chain.
	 *  Explicit false is not valid — use absence to express "no claim". */
	terminal?: true;
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
