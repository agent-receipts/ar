import { describe, expect, it } from "vitest";
import { generateKeyPair, open, seal } from "./hpke.js";

// RFC 7748 §6.1 well-known X25519 test keys. Published IETF vectors — not real secrets.
const ALICE_PUB_HEX =
	"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"; // skipcq: SCM-001
const ALICE_PRIV_HEX =
	"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"; // skipcq: SCM-001

// RFC 9180 §A.1.1 ephemeral seed (DHKEM(X25519) base-mode test vector). DeriveKeyPair(ikmE)
// yields skEm whose public key is pkEm = 37fda3… — base64url N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE.
const RFC9180_A11_IKME_HEX =
	"7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
const RFC9180_A11_PKEM_B64URL = "N_2jVnvb1ijohmjDyNfpfR0SU7bU6m1EwVD3QfG_RDE";

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return bytes;
}

describe("hpke kem", () => {
	it("derives the RFC 9180 §A.1.1 encapsulated key from its ikmE", () => {
		const ikmE = fromHex(RFC9180_A11_IKME_HEX);
		const { enc } = seal(
			fromHex(ALICE_PUB_HEX),
			new TextEncoder().encode("{}"),
			ikmE,
		);
		// enc depends only on ikmE via DeriveKeyPair, so it matches the RFC's pkEm
		// regardless of recipient. This pins the X25519 §7.1.3 DeriveKeyPair path.
		expect(Buffer.from(enc).toString("base64url")).toBe(
			RFC9180_A11_PKEM_B64URL,
		);
		expect(enc).toHaveLength(32);
	});
});

describe("hpke seal/open", () => {
	it("round-trips with the RFC 7748 Alice key pair", () => {
		const pt = new TextEncoder().encode("disclosure plaintext");
		const { enc, ct } = seal(fromHex(ALICE_PUB_HEX), pt);
		const got = open(fromHex(ALICE_PRIV_HEX), enc, ct);
		expect(Buffer.from(got).toString("utf-8")).toBe("disclosure plaintext");
	});

	it("round-trips with a freshly generated key pair", () => {
		const kp = generateKeyPair();
		expect(kp.publicKey).toHaveLength(32);
		expect(kp.privateKey).toHaveLength(32);
		const { enc, ct } = seal(kp.publicKey, new TextEncoder().encode("{}"));
		expect(new TextDecoder().decode(open(kp.privateKey, enc, ct))).toBe("{}");
	});

	it("produces a fresh ephemeral key (and ciphertext) per call without a seed", () => {
		const pub = fromHex(ALICE_PUB_HEX);
		const pt = new TextEncoder().encode("{}");
		const a = seal(pub, pt);
		const b = seal(pub, pt);
		expect(Buffer.from(a.enc).toString("hex")).not.toBe(
			Buffer.from(b.enc).toString("hex"),
		);
	});

	it("is deterministic given a fixed ikmE seed", () => {
		const pub = fromHex(ALICE_PUB_HEX);
		const ikmE = fromHex(RFC9180_A11_IKME_HEX);
		const pt = new TextEncoder().encode("{}");
		const a = seal(pub, pt, ikmE);
		const b = seal(pub, pt, ikmE);
		expect(Buffer.from(a.enc).toString("hex")).toBe(
			Buffer.from(b.enc).toString("hex"),
		);
		expect(Buffer.from(a.ct).toString("hex")).toBe(
			Buffer.from(b.ct).toString("hex"),
		);
	});

	it("fails to open with the wrong private key (GCM tag mismatch)", () => {
		const wrong = generateKeyPair();
		const { enc, ct } = seal(
			fromHex(ALICE_PUB_HEX),
			new TextEncoder().encode("{}"),
		);
		expect(() => open(wrong.privateKey, enc, ct)).toThrow();
	});

	it("fails to open tampered ciphertext", () => {
		const { enc, ct } = seal(
			fromHex(ALICE_PUB_HEX),
			new TextEncoder().encode("{}"),
		);
		const tampered = Uint8Array.from(ct);
		tampered[0] ^= 0x01;
		expect(() => open(fromHex(ALICE_PRIV_HEX), enc, tampered)).toThrow();
	});
});

describe("hpke input validation", () => {
	it("rejects a recipient public key that is not 32 bytes", () => {
		expect(() => seal(new Uint8Array(31), new Uint8Array(0))).toThrow(
			"32 bytes",
		);
	});

	it("rejects an ikmE seed that is not 32 bytes", () => {
		expect(() =>
			seal(fromHex(ALICE_PUB_HEX), new Uint8Array(0), new Uint8Array(16)),
		).toThrow("32 bytes");
	});

	it("rejects a recipient private key that is not 32 bytes on open", () => {
		const { enc, ct } = seal(
			fromHex(ALICE_PUB_HEX),
			new TextEncoder().encode("{}"),
		);
		expect(() => open(new Uint8Array(16), enc, ct)).toThrow("32 bytes");
	});

	it("rejects an enc that is not 32 bytes on open", () => {
		const { ct } = seal(fromHex(ALICE_PUB_HEX), new TextEncoder().encode("{}"));
		expect(() => open(fromHex(ALICE_PRIV_HEX), new Uint8Array(31), ct)).toThrow(
			"32 bytes",
		);
	});

	it("rejects a ciphertext too short to hold a GCM tag", () => {
		// 32-byte enc passes the length check, so open() reaches aeadOpen, which
		// guards the 16-byte tag minimum.
		const { enc } = seal(
			fromHex(ALICE_PUB_HEX),
			new TextEncoder().encode("{}"),
		);
		expect(() =>
			open(fromHex(ALICE_PRIV_HEX), enc, new Uint8Array(15)),
		).toThrow("too short");
	});
});

describe("hpke degenerate-key rejection", () => {
	// The all-zero X25519 public key is a low-order point: the DH output is the
	// all-zero shared secret RFC 7748 §6.1 warns about. We rely on OpenSSL's
	// X25519 to reject it at derivation time rather than producing that secret;
	// these tests pin that contract so a future DH-backend change can't silently
	// regress it.
	const LOW_ORDER = new Uint8Array(32); // 32 zero bytes

	it("rejects a low-order recipient public key on seal", () => {
		expect(() => seal(LOW_ORDER, new TextEncoder().encode("{}"))).toThrow(
			"invalid recipient public key",
		);
	});

	it("rejects a low-order enc on open", () => {
		const { ct } = seal(fromHex(ALICE_PUB_HEX), new TextEncoder().encode("{}"));
		expect(() => open(fromHex(ALICE_PRIV_HEX), LOW_ORDER, ct)).toThrow(
			"invalid encapsulated key",
		);
	});
});
