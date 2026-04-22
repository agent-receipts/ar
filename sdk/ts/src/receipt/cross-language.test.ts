import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyChain } from "./chain.js";
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

interface V020Vectors {
	version: string;
	keys: { publicKey: string; privateKey: string };
	responseHash: {
		rawResponse: Record<string, unknown>;
		redactedResponse: Record<string, unknown>;
		expectedHash: string;
	};
	terminalChain: {
		receipts: AgentReceipt[];
		expectedValid: boolean;
		expectedValidWithRequireTerminal: boolean;
	};
}

const currentDir = dirname(fileURLToPath(import.meta.url));

function loadGoVectors(): TestVectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/go_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

function loadV020Vectors(): V020Vectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/v020_vectors.json",
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
			const tampered: AgentReceipt = {
				...vectors.signing.signed,
				credentialSubject: {
					...vectors.signing.signed.credentialSubject,
					action: {
						...vectors.signing.signed.credentialSubject.action,
						type: "filesystem.file.delete",
					},
				},
			};
			expect(verifyReceipt(tampered, vectors.keys.publicKey)).toBe(false);
		});
	});
});

describe("cross-language: v0.2.0 vectors", () => {
	it("response_hash canonicalization matches Go", () => {
		const v = loadV020Vectors();
		expect(sha256(canonicalize(v.responseHash.redactedResponse))).toBe(
			v.responseHash.expectedHash,
		);
	});

	it("Go-signed terminal chain verifies in TypeScript", () => {
		const v = loadV020Vectors();
		const result = verifyChain(v.terminalChain.receipts, v.keys.publicKey);
		expect(result.valid).toBe(true);
	});

	it("Go-signed terminal chain passes requireTerminal in TypeScript", () => {
		const v = loadV020Vectors();
		const result = verifyChain(v.terminalChain.receipts, v.keys.publicKey, {
			requireTerminal: true,
		});
		expect(result.valid).toBe(true);
	});

	it("last receipt in Go chain has terminal: true", () => {
		const v = loadV020Vectors();
		const last = v.terminalChain.receipts.at(-1);
		expect(last?.credentialSubject.chain.terminal).toBe(true);
	});
});
