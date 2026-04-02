import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashReceipt } from "../receipt/hash.js";
import { generateKeyPair, signReceipt } from "../receipt/signing.js";
import { makeUnsigned } from "../test-utils/receipts.js";
import type { ReceiptStore } from "./store.js";
import { openStore } from "./store.js";
import { verifyStoredChain } from "./verify.js";

describe("verifyStoredChain", () => {
	let store: ReceiptStore;
	let publicKey: string;
	let privateKey: string;

	beforeEach(() => {
		store = openStore(":memory:");
		const keys = generateKeyPair();
		publicKey = keys.publicKey;
		privateKey = keys.privateKey;
	});

	afterEach(() => {
		store.close();
	});

	it("verifies a valid stored chain", () => {
		let previousHash: string | null = null;
		for (let i = 1; i <= 3; i++) {
			const unsigned = makeUnsigned(i, previousHash);
			const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
			const hash = hashReceipt(signed);
			store.insert(signed, hash);
			previousHash = hash;
		}

		const result = verifyStoredChain(store, "chain_test", publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(3);
	});

	it("detects tampered receipt in store", () => {
		const unsigned = makeUnsigned(1, null);
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		const hash = hashReceipt(signed);

		// Tamper before storing
		signed.credentialSubject.action.risk_level = "critical";
		store.insert(signed, hash);

		const result = verifyStoredChain(store, "chain_test", publicKey);

		expect(result.valid).toBe(false);
		expect(result.receipts[0]?.signatureValid).toBe(false);
	});

	it("returns valid for empty chain", () => {
		const result = verifyStoredChain(store, "nonexistent", publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(0);
	});

	it("detects broken hash link in stored chain", () => {
		// Insert first receipt normally
		const first = signReceipt(
			makeUnsigned(1, null),
			privateKey,
			"did:agent:test#key-1",
		);
		store.insert(first, hashReceipt(first));

		// Insert second receipt with wrong previous hash
		const second = signReceipt(
			makeUnsigned(2, "sha256:wrong"),
			privateKey,
			"did:agent:test#key-1",
		);
		store.insert(second, hashReceipt(second));

		const result = verifyStoredChain(store, "chain_test", publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(1);
		expect(result.receipts[1]?.hashLinkValid).toBe(false);
	});

	it("verifies only the requested chain", () => {
		// Insert into two different chains
		for (const chainId of ["chain_a", "chain_b"]) {
			const unsigned = makeUnsigned(1, null, chainId);
			const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
			store.insert(signed, hashReceipt(signed));
		}

		const result = verifyStoredChain(store, "chain_a", publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(1);
	});
});
