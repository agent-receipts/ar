/**
 * HPKE disclosure envelope for parameters_disclosure (ADR-0012, amendment 2026-05-18).
 *
 * Ciphersuite: hpke-x25519-hkdf-sha256-aes-256-gcm
 * (RFC 9180, KEM=DHKEM(X25519,HKDF-SHA256) 0x0020, KDF=HKDF-SHA256 0x0001, AEAD=AES-256-GCM 0x0002)
 */

import {
	Aes256Gcm,
	CipherSuite,
	DhkemX25519HkdfSha256,
	HkdfSha256,
} from "@hpke/core";
import { canonicalize, isPlainObject } from "./hash.js";

const V1_ALG = "hpke-x25519-hkdf-sha256-aes-256-gcm" as const;

// Module-level suite — stateless, safe to reuse across calls.
const SUITE = new CipherSuite({
	kem: new DhkemX25519HkdfSha256(),
	kdf: new HkdfSha256(),
	aead: new Aes256Gcm(),
});

/** One entry in the recipients array. Field names match RFC 9180 §4.1 ("enc", not "encap"). */
export interface DisclosureRecipient {
	kid: string;
	enc: string; // HPKE encapsulated key; unpadded base64url, exactly 43 chars for X25519
}

/**
 * v1 asymmetric encryption envelope for parameters_disclosure (ADR-0012).
 * The signed receipt commits to the ciphertext; only the forensic private key
 * holder can recover the plaintext.
 */
export interface DisclosureEnvelope {
	v: "1";
	alg: typeof V1_ALG;
	recipients: [DisclosureRecipient]; // length-1 tuple enforces v1 single-recipient constraint
	ct: string; // AEAD ciphertext; unpadded base64url
}

/**
 * Raw X25519 key bytes (32 bytes each) for forensic disclosure.
 * Separate from the Ed25519 signing key pair per ADR-0001 / ADR-0012.
 */
export interface ForensicKeyPair {
	/** 32-byte X25519 public key. Share with emitters so they can encrypt disclosures. */
	publicKey: Uint8Array;
	/** 32-byte X25519 private key. Keep offline; required to decrypt disclosures. */
	privateKey: Uint8Array;
}

function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
	return Buffer.from(
		buf instanceof Uint8Array ? buf : new Uint8Array(buf),
	).toString("base64url");
}

function fromBase64Url(s: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]+$/.test(s)) {
		throw new Error(
			"invalid base64url: must use only unpadded base64url characters [A-Za-z0-9_-]",
		);
	}
	return Buffer.from(s, "base64url");
}

/**
 * Generates an X25519 key pair for forensic disclosure.
 * The public key is shared with emitters; the private key must be kept offline.
 */
export async function generateForensicKeyPair(): Promise<ForensicKeyPair> {
	const kp = await SUITE.kem.generateKeyPair();
	const pubBytes = await SUITE.kem.serializePublicKey(kp.publicKey);
	const privBytes = await SUITE.kem.serializePrivateKey(kp.privateKey);
	return {
		publicKey: new Uint8Array(pubBytes),
		privateKey: new Uint8Array(privBytes),
	};
}

/**
 * Encrypts params as a v1 HPKE disclosure envelope.
 *
 * params is RFC 8785 JCS-canonicalized before encryption so all SDKs encrypt
 * the same bytes for the same parameters object.
 *
 * @param params - The parameters to encrypt (must be a plain object, not null/array).
 * @param recipientPublicKey - 32-byte X25519 forensic public key.
 * @param kid - Recipient key identifier (did:key DID URL or sha256:<hex> fingerprint).
 */
export async function encryptDisclosure(
	params: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
): Promise<DisclosureEnvelope> {
	if (
		params === null ||
		params === undefined ||
		typeof params !== "object" ||
		Array.isArray(params)
	) {
		throw new Error("params must be a plain object");
	}
	if (recipientPublicKey.byteLength !== 32) {
		throw new Error(
			`recipientPublicKey must be 32 bytes, got ${recipientPublicKey.byteLength}`,
		);
	}
	if (!kid) {
		throw new Error("kid must not be empty");
	}
	return encryptWithOptions(params, recipientPublicKey, kid, undefined);
}

/**
 * Deterministic variant of encryptDisclosure for cross-SDK test vectors.
 * ikmE (32 bytes) is passed as the ephemeral key material; @hpke/core internally
 * applies DHKEM(X25519) DeriveKeyPair (RFC 9180 §4.1 HKDF derivation) to produce
 * the ephemeral scalar — it does NOT use ikmE directly as the scalar. This is
 * confirmed by vector-1: ikmE = RFC 9180 §A.1.1 ikmE → enc = RFC 9180 §A.1.1 pkEm.
 *
 * @internal FOR TESTING ONLY. Reusing ikmE across real encryptions breaks confidentiality.
 */
export async function encryptDisclosureWithSeed(
	params: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
	ikmE: Uint8Array,
): Promise<DisclosureEnvelope> {
	if (ikmE.byteLength !== 32) {
		throw new Error(`ikmE must be 32 bytes, got ${ikmE.byteLength}`);
	}
	return encryptWithOptions(params, recipientPublicKey, kid, ikmE);
}

async function encryptWithOptions(
	params: Record<string, unknown>,
	recipientPublicKey: Uint8Array,
	kid: string,
	ikmE: Uint8Array | undefined,
): Promise<DisclosureEnvelope> {
	const pubKey = await SUITE.kem.deserializePublicKey(recipientPublicKey);

	// RFC 8785 JCS before encryption — cross-SDK interop depends on this.
	const canonical = canonicalize(params);

	// info="" (omitted = library default EMPTY) and AAD="" per ADR-0012 amendment §8.
	const sender = await SUITE.createSenderContext({
		recipientPublicKey: pubKey,
		...(ikmE !== undefined ? { ekm: ikmE } : {}),
	});

	const ct = await sender.seal(
		new TextEncoder().encode(canonical),
		new Uint8Array(0), // AAD = ""
	);

	return {
		v: "1",
		alg: V1_ALG,
		recipients: [{ kid, enc: toBase64Url(sender.enc) }],
		ct: toBase64Url(ct),
	};
}

/**
 * Recovers the plaintext parameters from a v1 HPKE disclosure envelope.
 * @param env - The disclosure envelope to decrypt.
 * @param recipientPrivateKey - 32-byte X25519 forensic private key.
 */
export async function decryptDisclosure(
	env: DisclosureEnvelope,
	recipientPrivateKey: Uint8Array,
): Promise<Record<string, unknown>> {
	if (env == null) {
		throw new Error("disclosure envelope must not be null or undefined");
	}
	if (env.v !== "1") {
		throw new Error(`unsupported envelope version "${env.v}"`);
	}
	if (env.alg !== V1_ALG) {
		throw new Error(`unsupported algorithm "${env.alg}"`);
	}
	if (!Array.isArray(env.recipients) || env.recipients.length !== 1) {
		throw new Error(
			`v1 envelope must have exactly 1 recipient, got ${env.recipients?.length ?? 0}`,
		);
	}
	if (recipientPrivateKey.byteLength !== 32) {
		throw new Error(
			`recipientPrivateKey must be 32 bytes, got ${recipientPrivateKey.byteLength}`,
		);
	}

	const privKey = await SUITE.kem.deserializePrivateKey(recipientPrivateKey);

	const enc = fromBase64Url(env.recipients[0].enc);
	if (enc.byteLength !== 32) {
		throw new Error(
			`invalid enc: expected 32 bytes (X25519 encapsulated key), got ${enc.byteLength}`,
		);
	}
	const ct = fromBase64Url(env.ct);

	const receiver = await SUITE.createRecipientContext({
		recipientKey: privKey,
		enc,
	});

	const plaintext = await receiver.open(ct, new Uint8Array(0)); // AAD = ""

	const result: unknown = JSON.parse(new TextDecoder().decode(plaintext));
	if (!isPlainObject(result)) {
		throw new Error("decrypted plaintext is not a JSON object");
	}
	return result;
}
