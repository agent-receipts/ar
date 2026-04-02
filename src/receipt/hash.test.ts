import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalize, hashReceipt, sha256 } from "./hash.js";
import type { AgentReceipt } from "./types.js";
import { CONTEXT, CREDENTIAL_TYPE, VERSION } from "./types.js";

describe("canonicalize", () => {
	it("sorts object keys lexicographically", () => {
		expect(canonicalize({ z: 1, a: 2 })).toBe('{"a":2,"z":1}');
	});

	it("recursively sorts nested object keys", () => {
		expect(canonicalize({ b: { d: 1, c: 2 }, a: 3 })).toBe(
			'{"a":3,"b":{"c":2,"d":1}}',
		);
	});

	it("preserves array order", () => {
		expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
	});

	it("handles null", () => {
		expect(canonicalize(null)).toBe("null");
	});

	it("handles booleans", () => {
		expect(canonicalize(true)).toBe("true");
		expect(canonicalize(false)).toBe("false");
	});

	it("handles strings with escaping", () => {
		expect(canonicalize('hello "world"')).toBe('"hello \\"world\\""');
	});

	it("produces no whitespace", () => {
		const result = canonicalize({ a: [1, 2], b: { c: "d" } });
		expect(result).not.toMatch(/\s/);
	});

	it("handles negative zero as zero", () => {
		expect(canonicalize(-0)).toBe("0");
	});

	it("throws for non-finite numbers", () => {
		expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(
			"non-finite numbers",
		);
		expect(() => canonicalize(Number.NaN)).toThrow("non-finite numbers");
	});

	it("throws for undefined", () => {
		expect(() => canonicalize(undefined)).toThrow(
			"undefined is not a valid JSON",
		);
	});

	it("throws for non-plain objects", () => {
		expect(() => canonicalize(new Date())).toThrow("non-plain objects");
		expect(() => canonicalize(new Map())).toThrow("non-plain objects");
	});

	it("throws for unsupported types", () => {
		expect(() => canonicalize(BigInt(1))).toThrow("unsupported type");
		expect(() => canonicalize(Symbol("x"))).toThrow("unsupported type");
	});

	it("handles empty objects and arrays", () => {
		expect(canonicalize({})).toBe("{}");
		expect(canonicalize([])).toBe("[]");
	});

	it("handles mixed nested structures", () => {
		const input = {
			credentialSubject: {
				chain: { sequence: 1, chain_id: "abc", previous_receipt_hash: null },
				action: { type: "filesystem.file.read", id: "act_001" },
			},
		};
		const result = canonicalize(input);
		// Keys should be sorted at every level
		expect(result).toBe(
			'{"credentialSubject":{"action":{"id":"act_001","type":"filesystem.file.read"},"chain":{"chain_id":"abc","previous_receipt_hash":null,"sequence":1}}}',
		);
	});
});

describe("sha256", () => {
	it("returns sha256:<hex> format", () => {
		const result = sha256("hello");
		expect(result).toMatch(/^sha256:[0-9a-f]{64}$/);
	});

	it("matches Node.js crypto output", () => {
		const expected = createHash("sha256")
			.update("hello", "utf-8")
			.digest("hex");
		expect(sha256("hello")).toBe(`sha256:${expected}`);
	});

	it("produces different hashes for different inputs", () => {
		expect(sha256("a")).not.toBe(sha256("b"));
	});
});

describe("hashReceipt", () => {
	function makeReceipt(): AgentReceipt {
		return {
			"@context": CONTEXT,
			id: "urn:receipt:test-hash",
			type: CREDENTIAL_TYPE,
			version: VERSION,
			issuer: { id: "did:agent:test" },
			issuanceDate: "2026-03-29T14:31:00Z",
			credentialSubject: {
				principal: { id: "did:user:test" },
				action: {
					id: "act_001",
					type: "filesystem.file.read",
					risk_level: "low",
					timestamp: "2026-03-29T14:31:00Z",
				},
				outcome: { status: "success" },
				chain: {
					sequence: 1,
					previous_receipt_hash: null,
					chain_id: "chain_test",
				},
			},
			proof: {
				type: "Ed25519Signature2020",
				proofValue: "utest-signature",
			},
		};
	}

	it("returns sha256:<hex> format", () => {
		expect(hashReceipt(makeReceipt())).toMatch(/^sha256:[0-9a-f]{64}$/);
	});

	it("excludes proof from hash computation", () => {
		const a = makeReceipt();
		const b = makeReceipt();
		b.proof.proofValue = "udifferent-signature";

		expect(hashReceipt(a)).toBe(hashReceipt(b));
	});

	it("produces different hashes for different receipt content", () => {
		const a = makeReceipt();
		const b = makeReceipt();
		b.id = "urn:receipt:different";

		expect(hashReceipt(a)).not.toBe(hashReceipt(b));
	});

	it("is deterministic", () => {
		const receipt = makeReceipt();
		expect(hashReceipt(receipt)).toBe(hashReceipt(receipt));
	});
});
