import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize, hashReceipt } from "./hash.js";
import type { AgentReceipt } from "./types.js";

const vectorsPath = join(
	import.meta.dirname,
	"../../../../cross-sdk-tests/canonicalization_vectors.json",
);

interface VectorFile {
	canonicalization_vectors: CanonVector[];
	receipt_hash_vectors: ReceiptVector[];
}

interface CanonVector {
	name: string;
	input: unknown;
	canonical: string;
	expectedHash?: string;
}

interface ReceiptVector {
	name: string;
	receipt?: unknown;
	expectedHash?: string;
	mustContainSubstring?: string;
	receiptsFrom?: string;
}

const vectors: VectorFile = JSON.parse(readFileSync(vectorsPath, "utf-8"));

describe("canonicalization_vectors", () => {
	for (const v of vectors.canonicalization_vectors) {
		it(v.name, () => {
			expect(canonicalize(v.input)).toBe(v.canonical);

			if (v.expectedHash && v.expectedHash !== "COMPUTE_AT_COMMIT_TIME") {
				const hash =
					"sha256:" +
					createHash("sha256").update(v.canonical, "utf-8").digest("hex");
				expect(hash).toBe(v.expectedHash);
			}
		});
	}
});

describe("receipt_hash_vectors", () => {
	// Build a lookup for SAME_AS_ references.
	const resolved = new Map<string, string>();
	for (const v of vectors.receipt_hash_vectors) {
		if (
			v.expectedHash &&
			v.expectedHash !== "COMPUTE_AT_COMMIT_TIME" &&
			!v.expectedHash.startsWith("SAME_AS_")
		) {
			resolved.set(v.name, v.expectedHash);
		}
	}

	for (const v of vectors.receipt_hash_vectors) {
		if (!v.receipt) continue; // skip receiptsFrom reference vectors

		it(v.name, () => {
			const gotHash = hashReceipt(v.receipt as AgentReceipt);

			if (v.mustContainSubstring) {
				expect(canonicalize(v.receipt)).toContain(v.mustContainSubstring);
			}

			if (!v.expectedHash || v.expectedHash === "COMPUTE_AT_COMMIT_TIME") {
				return;
			}

			let expected = v.expectedHash;
			if (expected.startsWith("SAME_AS_")) {
				const refName = expected.slice("SAME_AS_".length);
				const ref = resolved.get(refName);
				expect(ref, `SAME_AS_ reference '${refName}' not found`).toBeDefined();
				expected = ref as string;
			}

			expect(gotHash).toBe(expected);
		});
	}
});
