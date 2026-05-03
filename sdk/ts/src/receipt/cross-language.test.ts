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
	parametersDisclosureReceipt: {
		description: string;
		receipt: AgentReceipt;
		expectedReceiptHash: string;
		expectedValid: boolean;
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

function loadPyVectors(): TestVectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/py_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

interface MalformedVectors {
	description: string;
	keys: { publicKey: string; privateKey: string };
	receipts: Array<{ name: string; description: string; receipt: AgentReceipt }>;
	chains: Array<{
		name: string;
		description: string;
		receipts: AgentReceipt[];
	}>;
}

function loadMalformedVectors(): MalformedVectors {
	const path = resolve(
		currentDir,
		"../../../../cross-sdk-tests/malformed_vectors.json",
	);
	return JSON.parse(readFileSync(path, "utf-8"));
}

function safeVerify(receipt: AgentReceipt, publicKey: string): boolean {
	try {
		return verifyReceipt(receipt, publicKey);
	} catch {
		return false;
	}
}

function safeVerifyChain(receipts: AgentReceipt[], publicKey: string): boolean {
	try {
		return verifyChain(receipts, publicKey).valid === true;
	} catch {
		return false;
	}
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

describe("cross-language: Python SDK", () => {
	describe("canonicalization matches Python", () => {
		it("simple object", () => {
			const vectors = loadPyVectors();
			expect(canonicalize(vectors.canonicalization.simpleInput)).toBe(
				vectors.canonicalization.simpleExpected,
			);
		});

		it("unsigned receipt", () => {
			const vectors = loadPyVectors();
			expect(canonicalize(vectors.canonicalization.receiptInput)).toBe(
				vectors.canonicalization.receiptExpected,
			);
		});
	});

	describe("SHA-256 hashing matches Python", () => {
		it("simple string", () => {
			const vectors = loadPyVectors();
			expect(sha256(vectors.hashing.simpleInput)).toBe(
				vectors.hashing.simpleExpected,
			);
		});

		it("receipt hash", () => {
			const vectors = loadPyVectors();
			expect(hashReceipt(vectors.signing.signed)).toBe(
				vectors.hashing.receiptExpected,
			);
		});
	});

	describe("Python-signed receipt verification", () => {
		it("verifies in TypeScript", () => {
			const vectors = loadPyVectors();
			expect(
				verifyReceipt(vectors.signing.signed, vectors.keys.publicKey),
			).toBe(true);
		});

		it("fails with wrong key", () => {
			const vectors = loadPyVectors();
			const other = generateKeyPair();
			expect(verifyReceipt(vectors.signing.signed, other.publicKey)).toBe(
				false,
			);
		});

		it("fails when tampered", () => {
			const vectors = loadPyVectors();
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

	it("Go-signed parameters_disclosure receipt verifies in TypeScript", () => {
		const v = loadV020Vectors();
		expect(
			verifyReceipt(v.parametersDisclosureReceipt.receipt, v.keys.publicKey),
		).toBe(true);
	});

	it("parameters_disclosure receipt hash matches Go", () => {
		const v = loadV020Vectors();
		expect(hashReceipt(v.parametersDisclosureReceipt.receipt)).toBe(
			v.parametersDisclosureReceipt.expectedReceiptHash,
		);
	});
});

describe("cross-language: malformed corpus", () => {
	it("the corpus contains receipt cases", () => {
		const v = loadMalformedVectors();
		expect(v.receipts.length).toBeGreaterThan(0);
	});

	it("rejects every malformed receipt case", () => {
		const v = loadMalformedVectors();
		const accepted = v.receipts
			.filter(({ receipt }) => safeVerify(receipt, v.keys.publicKey))
			.map(({ name }) => name);
		expect(accepted).toEqual([]);
	});

	it("rejects every malformed chain case", () => {
		const v = loadMalformedVectors();
		const accepted = v.chains
			.filter(({ receipts }) => safeVerifyChain(receipts, v.keys.publicKey))
			.map(({ name }) => name);
		expect(accepted).toEqual([]);
	});
});
