import { describe, expect, it } from "vitest";
import { makeUnsigned } from "../test-utils/receipts.js";
import { verifyChain } from "./chain.js";
import { hashReceipt } from "./hash.js";
import { generateKeyPair, signReceipt } from "./signing.js";

function buildChain(count: number, privateKey: string) {
	const receipts = [];
	let previousHash: string | null = null;

	for (let i = 1; i <= count; i++) {
		const unsigned = makeUnsigned(i, previousHash);
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		receipts.push(signed);
		previousHash = hashReceipt(signed);
	}

	return receipts;
}

describe("verifyChain", () => {
	it("returns valid for an empty chain", () => {
		const { publicKey } = generateKeyPair();
		const result = verifyChain([], publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(0);
		expect(result.brokenAt).toBe(-1);
	});

	it("verifies a single receipt", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(1, privateKey);
		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(1);
		expect(result.receipts[0]?.signatureValid).toBe(true);
		expect(result.receipts[0]?.hashLinkValid).toBe(true);
		expect(result.receipts[0]?.sequenceValid).toBe(true);
	});

	it("verifies a valid 3-receipt chain", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);
		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(3);
		expect(result.brokenAt).toBe(-1);

		for (const r of result.receipts) {
			expect(r.signatureValid).toBe(true);
			expect(r.hashLinkValid).toBe(true);
			expect(r.sequenceValid).toBe(true);
		}
	});

	it("detects a tampered receipt (broken signature)", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);

		// Tamper with the second receipt
		const tampered = chain[1];
		if (tampered) tampered.credentialSubject.action.risk_level = "critical";

		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(1);
		expect(result.receipts[0]?.signatureValid).toBe(true);
		expect(result.receipts[1]?.signatureValid).toBe(false);
	});

	it("detects a broken hash link", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);

		// Replace the second receipt with one that has wrong previous_hash
		const badUnsigned = makeUnsigned(2, "sha256:wrong");
		chain[1] = signReceipt(badUnsigned, privateKey, "did:agent:test#key-1");

		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(1);
		expect(result.receipts[1]?.hashLinkValid).toBe(false);
	});

	it("detects a broken sequence", () => {
		const { publicKey, privateKey } = generateKeyPair();

		// Build chain with gap: sequence 1, 3
		const first = signReceipt(
			makeUnsigned(1, null),
			privateKey,
			"did:agent:test#key-1",
		);
		const firstHash = hashReceipt(first);
		const second = signReceipt(
			makeUnsigned(3, firstHash),
			privateKey,
			"did:agent:test#key-1",
		);

		const result = verifyChain([first, second], publicKey);

		expect(result.valid).toBe(false);
		expect(result.receipts[1]?.sequenceValid).toBe(false);
	});

	it("detects wrong signing key", () => {
		const signer = generateKeyPair();
		const other = generateKeyPair();
		const chain = buildChain(2, signer.privateKey);

		const result = verifyChain(chain, other.publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(0);
		expect(result.receipts[0]?.signatureValid).toBe(false);
	});

	it("first receipt must have null previous_receipt_hash", () => {
		const { publicKey, privateKey } = generateKeyPair();

		const bad = signReceipt(
			makeUnsigned(1, "sha256:unexpected"),
			privateKey,
			"did:agent:test#key-1",
		);

		const result = verifyChain([bad], publicKey);

		expect(result.valid).toBe(false);
		expect(result.receipts[0]?.hashLinkValid).toBe(false);
	});

	it("continues verifying after a break", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);

		// Tamper with second receipt
		const tampered = chain[1];
		if (tampered) tampered.credentialSubject.action.risk_level = "critical";

		const result = verifyChain(chain, publicKey);

		// Should still have results for all 3 receipts
		expect(result.receipts).toHaveLength(3);
		expect(result.brokenAt).toBe(1);

		// Tampered receipt: signature invalid, but hash link to first is still valid
		expect(result.receipts[1]?.signatureValid).toBe(false);
		expect(result.receipts[1]?.hashLinkValid).toBe(true);

		// Third receipt: own signature valid, but hash link to tampered second is broken
		expect(result.receipts[2]?.signatureValid).toBe(true);
		expect(result.receipts[2]?.hashLinkValid).toBe(false);
	});
});
