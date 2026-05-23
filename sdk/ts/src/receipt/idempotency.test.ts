import { describe, expect, it } from "vitest";
import { verifyChain } from "./chain.js";
import { createReceipt } from "./create.js";
import { canonicalize, hashReceipt } from "./hash.js";
import { agentReceiptSchema } from "./schema.js";
import { generateKeyPair, signReceipt } from "./signing.js";
import type { AgentReceipt } from "./types.js";

// buildChainWithKeys builds a signed, hash-linked chain whose i-th receipt
// carries idempotencyKeys[i] on action.idempotency_key (undefined = omitted).
function buildChainWithKeys(
	idempotencyKeys: (string | undefined)[],
	privateKey: string,
): AgentReceipt[] {
	const receipts: AgentReceipt[] = [];
	let previousHash: string | null = null;
	idempotencyKeys.forEach((key, i) => {
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: {
				type: "filesystem.file.read",
				risk_level: "low",
				...(key !== undefined && { idempotency_key: key }),
			},
			outcome: { status: "success" },
			chain: {
				sequence: i + 1,
				previous_receipt_hash: previousHash,
				chain_id: "chain_test",
			},
		});
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		receipts.push(signed);
		previousHash = hashReceipt(signed);
	});
	return receipts;
}

describe("idempotency_key", () => {
	it("createReceipt stamps action.idempotency_key", () => {
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:alice" },
			action: {
				type: "filesystem.file.read",
				risk_level: "low",
				idempotency_key: "req-1",
			},
			outcome: { status: "success" },
			chain: { sequence: 1, previous_receipt_hash: null, chain_id: "c" },
		});
		expect(unsigned.credentialSubject.action.idempotency_key).toBe("req-1");
	});

	it("omits idempotency_key from the canonical form when unset", () => {
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:alice" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: { sequence: 1, previous_receipt_hash: null, chain_id: "c" },
		});
		expect(canonicalize(unsigned)).not.toContain("idempotency_key");
	});

	it("drops an empty idempotency_key instead of emitting it (spec §7.3.6)", () => {
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:alice" },
			action: {
				type: "filesystem.file.read",
				risk_level: "low",
				idempotency_key: "",
			},
			outcome: { status: "success" },
			chain: { sequence: 1, previous_receipt_hash: null, chain_id: "c" },
		});
		expect(unsigned.credentialSubject.action.idempotency_key).toBeUndefined();
		expect(canonicalize(unsigned)).not.toContain("idempotency_key");
	});

	it("rejects an empty idempotency_key in schema validation", () => {
		const { privateKey } = generateKeyPair();
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:alice" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: { sequence: 1, previous_receipt_hash: null, chain_id: "c" },
		});
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		const bad = {
			...signed,
			credentialSubject: {
				...signed.credentialSubject,
				action: { ...signed.credentialSubject.action, idempotency_key: "" },
			},
		};
		expect(agentReceiptSchema.safeParse(bad).success).toBe(false);
	});

	it("surfaces a duplicate idempotency_key as a warning, not a failure", () => {
		const { publicKey, privateKey } = generateKeyPair();
		// Receipts 0 and 2 share "req-A"; receipt 1 has a distinct key.
		const chain = buildChainWithKeys(["req-A", "req-B", "req-A"], privateKey);

		const result = verifyChain(chain, publicKey);
		expect(result.valid).toBe(true);
		expect(result.warnings).toHaveLength(1);
		expect(result.warnings?.[0]).toContain("req-A");
		expect(result.warnings?.[0]).toContain("0");
		expect(result.warnings?.[0]).toContain("2");
	});

	it("emits no warnings for distinct or absent keys", () => {
		const { publicKey, privateKey } = generateKeyPair();
		for (const keys of [
			["req-1", "req-2", "req-3"],
			[undefined, undefined, undefined],
			["req-1", undefined, "req-2"],
		]) {
			const chain = buildChainWithKeys(keys, privateKey);
			const result = verifyChain(chain, publicKey);
			expect(result.valid).toBe(true);
			expect(result.warnings).toBeUndefined();
		}
	});
});
