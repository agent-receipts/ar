import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize, hashReceipt, sha256 } from "./hash.js";
import { generateKeyPair, verifyReceipt } from "./signing.js";
import type { AgentReceipt } from "./types.js";

interface TestVectors {
	keys: { publicKey: string; privateKey: string };
	canonicalization: {
		simpleInput: unknown;
		simpleExpected: string;
		receiptInput: unknown;
		receiptExpected: string;
	};
	hashing: {
		simpleInput: string;
		simpleExpected: string;
		receiptExpected: string;
	};
	signing: {
		unsigned: unknown;
		signed: AgentReceipt;
		verificationMethod: string;
	};
}

function loadGoVectors(): TestVectors {
	const path = resolve(
		__dirname,
		"../../../../cross-sdk-tests/go_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

describe("cross-language: Go SDK", () => {
	describe("canonicalization matches Go", () => {
		it("simple object", () => {
			const vectors = loadGoVectors();
			expect(canonicalize(vectors.canonicalization.simpleInput)).toBe(
				vectors.canonicalization.simpleExpected,
			);
		});

		it("unsigned receipt", () => {
			const vectors = loadGoVectors();
			expect(canonicalize(vectors.canonicalization.receiptInput)).toBe(
				vectors.canonicalization.receiptExpected,
			);
		});
	});

	describe("SHA-256 hashing matches Go", () => {
		it("simple string", () => {
			const vectors = loadGoVectors();
			expect(sha256(vectors.hashing.simpleInput)).toBe(
				vectors.hashing.simpleExpected,
			);
		});

		it("receipt hash", () => {
			const vectors = loadGoVectors();
			expect(hashReceipt(vectors.signing.signed)).toBe(
				vectors.hashing.receiptExpected,
			);
		});
	});

	describe("Go-signed receipt verification", () => {
		it("verifies in TypeScript", () => {
			const vectors = loadGoVectors();
			expect(
				verifyReceipt(vectors.signing.signed, vectors.keys.publicKey),
			).toBe(true);
		});

		it("fails with wrong key", () => {
			const vectors = loadGoVectors();
			const other = generateKeyPair();
			expect(verifyReceipt(vectors.signing.signed, other.publicKey)).toBe(
				false,
			);
		});

		it("fails when tampered", () => {
			const vectors = loadGoVectors();
			const tampered = {
				...vectors.signing.signed,
				credentialSubject: {
					...vectors.signing.signed.credentialSubject,
					action: {
						...vectors.signing.signed.credentialSubject.action,
						type: "filesystem.file.delete",
					},
				},
			};
			expect(
				verifyReceipt(tampered as AgentReceipt, vectors.keys.publicKey),
			).toBe(false);
		});
	});
});
