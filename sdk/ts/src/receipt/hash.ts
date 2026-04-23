import { createHash } from "node:crypto";
import type { AgentReceipt } from "./types.js";

function isPlainObject(v: unknown): v is Record<string, unknown> {
	if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
	// Prototype-based check so an object with a user-controlled "constructor"
	// key (valid JSON) isn't misclassified as non-plain.
	const proto = Object.getPrototypeOf(v);
	return proto === Object.prototype || proto === null;
}

// Returns a best-effort constructor name for a non-plain object, used only in
// error messages. Reads the prototype's constructor rather than v.constructor
// so a user-controlled "constructor" key can't leak through. Object.getPrototypeOf
// is typed as returning `any`, so no type assertion is needed.
function describeNonPlain(v: object): string {
	const proto = Object.getPrototypeOf(v);
	const name: unknown = proto?.constructor?.name;
	return typeof name === "string" ? name : "object";
}

/**
 * Serialize a value to canonical JSON per RFC 8785 (JSON Canonicalization Scheme).
 *
 * Key rules:
 * - Object keys are sorted lexicographically (by UTF-16 code units)
 * - Numbers use ECMAScript shortest representation (no trailing zeros; positive exponents may include '+')
 * - No whitespace between tokens
 * - Strings use minimal escaping (only required characters)
 * - null, boolean, and string values serialized per JSON spec
 */
export function canonicalize(value: unknown): string {
	if (value === null) return "null";
	if (value === undefined) {
		throw new Error("RFC 8785: undefined is not a valid JSON value");
	}
	if (typeof value === "boolean") return value ? "true" : "false";
	if (typeof value === "number") return canonicalizeNumber(value);
	if (typeof value === "string") return JSON.stringify(value);
	if (Array.isArray(value)) {
		return `[${value.map(canonicalize).join(",")}]`;
	}
	if (typeof value === "object") {
		if (!isPlainObject(value)) {
			throw new Error(
				`RFC 8785: non-plain objects are not valid JSON: ${describeNonPlain(value)}`,
			);
		}
		const keys = Object.keys(value).sort();
		const entries = keys.map(
			(k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`,
		);
		return `{${entries.join(",")}}`;
	}
	throw new Error(`RFC 8785: unsupported type: ${typeof value}`);
}

/**
 * RFC 8785 number serialization: use ES Number.toString() which already
 * produces the shortest representation for finite numbers.
 */
function canonicalizeNumber(n: number): string {
	if (!Number.isFinite(n)) {
		throw new Error(`RFC 8785: non-finite numbers are not valid JSON: ${n}`);
	}
	return Object.is(n, -0) ? "0" : String(n);
}

/**
 * Compute SHA-256 hash of a receipt, excluding the proof field.
 *
 * Applies ADR-0009 Rule 2 before canonicalising: optional fields whose value
 * is null are normalised to absent. The sole required-nullable field,
 * chain.previous_receipt_hash, is always emitted (including as JSON null).
 *
 * Returns the hash in "sha256:<hex>" format as used throughout the spec.
 */
export function hashReceipt(receipt: AgentReceipt): string {
	const { proof: _proof, ...unsigned } = receipt;
	const stripped = stripOptionalNulls(unsigned);
	// stripOptionalNulls drops null-valued keys, including
	// previous_receipt_hash when it is null. previous_receipt_hash is the sole
	// required-nullable field per ADR-0009; restore it so it is always emitted.
	const chain = pluckChain(stripped);
	if (chain) {
		chain.previous_receipt_hash =
			receipt.credentialSubject?.chain?.previous_receipt_hash ?? null;
	}
	return sha256(canonicalize(stripped));
}

function pluckChain(stripped: unknown): Record<string, unknown> | null {
	if (!isPlainObject(stripped)) return null;
	const cs = stripped.credentialSubject;
	if (!isPlainObject(cs)) return null;
	const chain = cs.chain;
	return isPlainObject(chain) ? chain : null;
}

/**
 * Recursively remove null-valued keys from plain objects (ADR-0009 Rule 2).
 * Optional fields must be absent when null; this enforces that at runtime.
 *
 * Non-plain objects (Date, Map, class instances) are passed through unchanged
 * so canonicalize() throws with its clearer error message rather than silently
 * coercing them to {}.
 */
function stripOptionalNulls(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(stripOptionalNulls);
	if (value !== null && typeof value === "object") {
		if (!isPlainObject(value)) return value;
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value)) {
			if (v !== null) out[k] = stripOptionalNulls(v);
		}
		return out;
	}
	return value;
}

/**
 * Compute SHA-256 hash of arbitrary data.
 *
 * Returns "sha256:<hex>" format.
 */
export function sha256(data: string): string {
	const hash = createHash("sha256").update(data, "utf-8").digest("hex");
	return `sha256:${hash}`;
}
