/**
 * Shared test factories for receipts.
 */
import type {
	AgentReceipt,
	OutcomeStatus,
	RiskLevel,
	UnsignedAgentReceipt,
} from "../receipt/types.js";
import { CONTEXT, CREDENTIAL_TYPE, VERSION } from "../receipt/types.js";

/**
 * Create a signed AgentReceipt with overridable fields.
 * Includes a dummy proof — use signReceipt() for real signatures.
 */
export function makeReceipt(
	overrides: {
		id?: string;
		sequence?: number;
		chainId?: string;
		actionType?: string;
		riskLevel?: RiskLevel;
		status?: OutcomeStatus;
		timestamp?: string;
		previousHash?: string | null;
	} = {},
): AgentReceipt {
	return {
		"@context": CONTEXT,
		id: overrides.id ?? "urn:receipt:test-1",
		type: CREDENTIAL_TYPE,
		version: VERSION,
		issuer: { id: "did:agent:test" },
		issuanceDate: "2026-03-29T14:00:00Z",
		credentialSubject: {
			principal: { id: "did:user:test" },
			action: {
				id: "act_1",
				type: overrides.actionType ?? "filesystem.file.read",
				risk_level: overrides.riskLevel ?? "low",
				timestamp: overrides.timestamp ?? "2026-03-29T14:00:00Z",
			},
			outcome: { status: overrides.status ?? "success" },
			chain: {
				sequence: overrides.sequence ?? 1,
				previous_receipt_hash: overrides.previousHash ?? null,
				chain_id: overrides.chainId ?? "chain_test",
			},
		},
		proof: { type: "Ed25519Signature2020", proofValue: "utest" },
	};
}

/**
 * Create an UnsignedAgentReceipt for chain/signing tests.
 */
export function makeUnsigned(
	sequence: number,
	previousHash: string | null,
	chainId = "chain_test",
): UnsignedAgentReceipt {
	return {
		"@context": CONTEXT,
		id: `urn:receipt:${chainId}-${sequence}`,
		type: CREDENTIAL_TYPE,
		version: VERSION,
		issuer: { id: "did:agent:test" },
		issuanceDate: "2026-03-29T14:31:00Z",
		credentialSubject: {
			principal: { id: "did:user:test" },
			action: {
				id: `act_${sequence}`,
				type: "filesystem.file.read",
				risk_level: "low",
				timestamp: "2026-03-29T14:31:00Z",
			},
			outcome: { status: "success" },
			chain: {
				sequence,
				previous_receipt_hash: previousHash,
				chain_id: chainId,
			},
		},
	};
}
