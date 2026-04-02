import { randomUUID } from "node:crypto";
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
			outcome: input.outcome,
			chain: input.chain,
			...(input.intent && { intent: input.intent }),
			...(input.authorization && { authorization: input.authorization }),
		},
	};
}
