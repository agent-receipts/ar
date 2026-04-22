import { randomUUID } from "node:crypto";
import { canonicalize, sha256 } from "./hash.js";
import type {
	Action,
	Authorization,
	Chain,
	Intent,
	Issuer,
	Outcome,
	Principal,
	UnsignedAgentReceipt,
} from "./types.js";
import { CONTEXT, CREDENTIAL_TYPE, VERSION } from "./types.js";

/**
 * Inputs for creating an unsigned receipt.
 *
 * Required fields match the mandatory parts of CredentialSubject.
 * Optional fields (intent, authorization) can be omitted.
 */
export interface CreateReceiptInput {
	issuer: Issuer;
	principal: Principal;
	action: Omit<Action, "id" | "timestamp">;
	outcome: Outcome;
	chain: Chain;
	intent?: Intent;
	authorization?: Authorization;
	/** Override the action timestamp (defaults to now). */
	actionTimestamp?: string;
	/** Pre-redacted response body to commit to. When provided, the SDK computes
	 *  response_hash = sha256(canonicalize(responseBody)) and stores it in outcome.
	 *  Caller must redact before passing (redact → hash → sign ordering). */
	responseBody?: unknown;
	/** When true, sets chain.terminal: true on the receipt. Never emits false. */
	terminal?: true;
}

/**
 * Build an unsigned Agent Receipt from structured inputs.
 *
 * Auto-generates: receipt id (URN UUID), action id, issuanceDate,
 * action timestamp, @context, type, and version.
 */
export function createReceipt(input: CreateReceiptInput): UnsignedAgentReceipt {
	const now = new Date().toISOString();
	const actionTimestamp = input.actionTimestamp ?? now;

	// Compute response_hash when response body is supplied.
	let responseHash: string | undefined;
	if (input.responseBody !== undefined) {
		responseHash = sha256(canonicalize(input.responseBody));
	}

	// Build outcome with optional response_hash.
	const outcome: Outcome = {
		...input.outcome,
		...(responseHash !== undefined && { response_hash: responseHash }),
	};

	// Build chain with optional terminal.
	const chain: Chain = {
		...input.chain,
		...(input.terminal && { terminal: true as const }),
	};

	return {
		"@context": CONTEXT,
		id: `urn:receipt:${randomUUID()}`,
		type: CREDENTIAL_TYPE,
		version: VERSION,
		issuer: input.issuer,
		issuanceDate: now,
		credentialSubject: {
			principal: input.principal,
			action: {
				...input.action,
				id: `act_${randomUUID()}`,
				timestamp: actionTimestamp,
			},
			outcome,
			chain,
			...(input.intent && { intent: input.intent }),
			...(input.authorization && { authorization: input.authorization }),
		},
	};
}
