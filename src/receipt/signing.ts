import { generateKeyPairSync, sign, verify } from "node:crypto";
import { canonicalize } from "./hash.js";
import type { AgentReceipt, Proof, UnsignedAgentReceipt } from "./types.js";

export interface KeyPair {
	publicKey: string;
	privateKey: string;
}

/** Multibase prefix for base64url (no padding) encoding. */
const MULTIBASE_BASE64URL = "u";

/**
 * Generate an Ed25519 key pair (PEM-encoded).
 *
 * Note: uses synchronous generation which blocks the event loop.
 * For long-running services, consider wrapping in a worker thread.
 */
export function generateKeyPair(): KeyPair {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
	return { publicKey, privateKey };
}

/**
 * Serialize an unsigned receipt to bytes using RFC 8785 canonicalization.
 */
function canonicalizeReceipt(receipt: UnsignedAgentReceipt): Buffer {
	return Buffer.from(canonicalize(receipt), "utf-8");
}

/**
 * Sign an unsigned receipt, returning a complete AgentReceipt with proof.
 */
export function signReceipt(
	unsigned: UnsignedAgentReceipt,
	privateKey: string,
	verificationMethod: string,
): AgentReceipt {
	const data = canonicalizeReceipt(unsigned);
	const signature = sign(null, data, privateKey);

	const proof: Proof = {
		type: "Ed25519Signature2020",
		created: new Date().toISOString(),
		verificationMethod,
		proofPurpose: "assertionMethod",
		proofValue: `${MULTIBASE_BASE64URL}${signature.toString("base64url")}`,
	};

	return { ...unsigned, proof };
}

/**
 * Verify the Ed25519 signature on a signed receipt.
 */
export function verifyReceipt(
	receipt: AgentReceipt,
	publicKey: string,
): boolean {
	const { proof, ...unsigned } = receipt;

	const proofValue = proof?.proofValue;
	if (
		typeof proofValue !== "string" ||
		proofValue.length < 2 ||
		!proofValue.startsWith(MULTIBASE_BASE64URL)
	) {
		return false;
	}

	const data = canonicalizeReceipt(unsigned as UnsignedAgentReceipt);
	const signature = Buffer.from(proofValue.slice(1), "base64url");

	return verify(null, data, publicKey, signature);
}
