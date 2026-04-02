import { createHash } from "node:crypto";
import type { AgentReceipt, UnsignedAgentReceipt } from "./types.js";

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
		if (
			value.constructor !== Object &&
			value.constructor !== undefined &&
			value.constructor !== null
		) {
			throw new Error(
				`RFC 8785: non-plain objects are not valid JSON: ${value.constructor.name}`,
			);
		}
		const keys = Object.keys(value).sort();
		const entries = keys.map(
			(k) =>
				`${JSON.stringify(k)}:${canonicalize((value as Record<string, unknown>)[k])}`,
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
 * Returns the hash in "sha256:<hex>" format as used throughout the spec.
 */
export function hashReceipt(receipt: AgentReceipt): string {
	const { proof: _, ...unsigned } = receipt;
	const canonical = canonicalize(unsigned as UnsignedAgentReceipt);
	return sha256(canonical);
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
