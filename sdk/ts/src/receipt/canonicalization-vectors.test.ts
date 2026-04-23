import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize, hashReceipt } from "./hash.js";
import { verifyReceipt } from "./signing.js";
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
	receipt?: AgentReceipt;
	expectedHash?: string;
	mustContainSubstring?: string;
	receiptsFrom?: string;
}

const vectors: VectorFile = JSON.parse(readFileSync(vectorsPath, "utf-8"));

interface V020VectorFile {
	keys: { publicKey: string; privateKey: string };
	terminalChain: { receipts: AgentReceipt[] };
}

function isRecord(v: unknown): v is Record<string, unknown> {
	return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isV020VectorFile(v: unknown): v is V020VectorFile {
	if (!isRecord(v)) return false;
	const keys = v.keys;
	if (!isRecord(keys) || typeof keys.publicKey !== "string") return false;
	const chain = v.terminalChain;
	if (!isRecord(chain)) return false;
	return Array.isArray(chain.receipts);
}

// Minimal shape check for an AgentReceipt loaded from a JSON fixture. Only
// validates the fields hashReceipt and verifyReceipt actually read; full
// schema validation is the verifier's job.
function isAgentReceipt(v: unknown): v is AgentReceipt {
	if (!isRecord(v)) return false;
	if (typeof v.id !== "string") return false;
	const proof = v.proof;
	if (!isRecord(proof) || typeof proof.proofValue !== "string") return false;
	return isRecord(v.credentialSubject);
}

function loadReferencedFile(relPath: string): unknown {
	const path = join(import.meta.dirname, "../../../..", relPath);
	return JSON.parse(readFileSync(path, "utf-8"));
}

// Resolves a "<file>#/json/pointer" reference to its target value.
function resolveReceiptsFrom(ref: string): {
	receipts: AgentReceipt[];
	publicKey: string;
} {
	const [filePath, pointer] = ref.split("#");
	if (!filePath || !pointer) {
		throw new Error(`receiptsFrom missing file or pointer: ${ref}`);
	}
	const root = loadReferencedFile(filePath);
	if (!isV020VectorFile(root)) {
		throw new Error(
			`receiptsFrom file ${filePath} does not match V020VectorFile shape`,
		);
	}
	let cursor: unknown = root;
	for (const segment of pointer.split("/").slice(1)) {
		if (!isRecord(cursor)) {
			throw new Error(`receiptsFrom invalid pointer ${ref} at '${segment}'`);
		}
		cursor = cursor[segment];
	}
	if (!Array.isArray(cursor)) {
		throw new Error(`receiptsFrom did not resolve to an array: ${ref}`);
	}
	const receipts: AgentReceipt[] = [];
	for (let i = 0; i < cursor.length; i++) {
		const item: unknown = cursor[i];
		if (!isAgentReceipt(item)) {
			throw new Error(
				`receiptsFrom ${ref}: element [${i}] is not a valid AgentReceipt`,
			);
		}
		receipts.push(item);
	}
	return { receipts, publicKey: root.keys.publicKey };
}

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
		const receiptsFrom = v.receiptsFrom;
		if (receiptsFrom) {
			// Reference vector — load the actual receipts and verify each still
			// signs under the post-sweep canonicaliser. The signature was made
			// over the pre-sweep canonical bytes; passing verification proves
			// those bytes are byte-for-byte identical to what we now produce.
			it(v.name, () => {
				const { receipts, publicKey } = resolveReceiptsFrom(receiptsFrom);
				expect(receipts.length).toBeGreaterThan(0);
				for (const r of receipts) {
					expect(verifyReceipt(r, publicKey), `receipt ${r.id}`).toBe(true);
				}
			});
			continue;
		}

		const receipt = v.receipt;
		if (!receipt) continue;

		it(v.name, () => {
			const gotHash = hashReceipt(receipt);

			if (v.mustContainSubstring) {
				expect(canonicalize(receipt)).toContain(v.mustContainSubstring);
			}

			if (!v.expectedHash || v.expectedHash === "COMPUTE_AT_COMMIT_TIME") {
				return;
			}

			let expected = v.expectedHash;
			if (expected.startsWith("SAME_AS_")) {
				const refName = expected.slice("SAME_AS_".length);
				const ref = resolved.get(refName);
				if (ref === undefined) {
					throw new Error(`SAME_AS_ reference '${refName}' not found`);
				}
				expected = ref;
			}

			expect(gotHash).toBe(expected);
		});
	}
});
