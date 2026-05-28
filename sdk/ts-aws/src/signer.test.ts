import {
	generateKeyPairSync,
	type KeyObject,
	sign as nodeSign,
	verify as nodeVerify,
} from "node:crypto";
import { describe, expect, it } from "vitest";
import type {
	KMSClient,
	KMSGetPublicKeyInput,
	KMSGetPublicKeyOutput,
	KMSSignInput,
	KMSSignOutput,
} from "./signer.js";
import { KMSSigner } from "./signer.js";

const TEST_KEY_ID = "arn:aws:kms:us-east-1:111122223333:key/test-ed25519";

/**
 * A hand-written {@link KMSClient}. Unset hooks fall back to a default backed
 * by an in-test Ed25519 key, so a signature produced by `sign` verifies against
 * the key returned by `getPublicKey` — mirroring the Go SDK's `mockKMS`.
 */
class MockKMS implements KMSClient {
	readonly publicKey: KeyObject;
	readonly #privateKey: KeyObject;
	readonly #spkiDer: Uint8Array;

	signInputs: KMSSignInput[] = [];
	getPubCalls = 0;
	signHook: ((input: KMSSignInput) => Promise<KMSSignOutput>) | undefined;
	getPubHook:
		| ((input: KMSGetPublicKeyInput) => Promise<KMSGetPublicKeyOutput>)
		| undefined;

	constructor() {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		this.publicKey = publicKey;
		this.#privateKey = privateKey;
		this.#spkiDer = new Uint8Array(
			publicKey.export({ type: "spki", format: "der" }),
		);
	}

	/** Raw 32-byte public key, for assertions. */
	rawPublicKey(): Uint8Array {
		const jwk = this.publicKey.export({ format: "jwk" }) as { x: string };
		return new Uint8Array(Buffer.from(jwk.x, "base64url"));
	}

	async sign(input: KMSSignInput): Promise<KMSSignOutput> {
		this.signInputs.push(input);
		if (this.signHook) {
			return this.signHook(input);
		}
		return {
			Signature: new Uint8Array(
				nodeSign(null, input.Message, this.#privateKey),
			),
		};
	}

	async getPublicKey(
		input: KMSGetPublicKeyInput,
	): Promise<KMSGetPublicKeyOutput> {
		this.getPubCalls++;
		if (this.getPubHook) {
			return this.getPubHook(input);
		}
		return { PublicKey: this.#spkiDer };
	}
}

function newSigner(mock: KMSClient): KMSSigner {
	return new KMSSigner(TEST_KEY_ID, { client: mock });
}

describe("KMSSigner construction", () => {
	it("rejects an empty keyId", () => {
		expect(() => new KMSSigner("", { client: new MockKMS() })).toThrow(
			/keyId must not be empty/,
		);
	});

	it("rejects a negative timeout", () => {
		expect(
			() =>
				new KMSSigner(TEST_KEY_ID, { client: new MockKMS(), timeoutMs: -1 }),
		).toThrow(/timeoutMs must not be negative/);
	});
});

describe("KMSSigner.sign", () => {
	it("returns a signature that verifies against the KMS public key", async () => {
		const mock = new MockKMS();
		const signer = newSigner(mock);

		const message = Buffer.from("canonical receipt bytes");
		const sig = await signer.sign(message);

		expect(nodeVerify(null, message, mock.publicKey, sig)).toBe(true);
	});

	it("calls kms:Sign with ED25519_SHA_512, RAW, and the keyId", async () => {
		const mock = new MockKMS();
		const signer = newSigner(mock);

		await signer.sign(Buffer.from("msg"));

		expect(mock.signInputs).toHaveLength(1);
		const input = mock.signInputs[0];
		expect(input?.SigningAlgorithm).toBe("ED25519_SHA_512");
		expect(input?.MessageType).toBe("RAW");
		expect(input?.KeyId).toBe(TEST_KEY_ID);
	});

	it("propagates KMS errors unchanged", async () => {
		const sentinel = new Error("AccessDeniedException: not authorized");
		const mock = new MockKMS();
		mock.signHook = () => Promise.reject(sentinel);
		const signer = newSigner(mock);

		await expect(signer.sign(Buffer.from("msg"))).rejects.toBe(sentinel);
	});
});

describe("KMSSigner.getPublicKey", () => {
	it("returns the raw 32-byte Ed25519 public key", async () => {
		const mock = new MockKMS();
		const signer = newSigner(mock);

		const got = await signer.getPublicKey();

		expect(got).toHaveLength(32);
		expect(Buffer.from(got)).toEqual(Buffer.from(mock.rawPublicKey()));
	});

	it("caches after the first call", async () => {
		const mock = new MockKMS();
		const signer = newSigner(mock);

		const first = await signer.getPublicKey();
		const second = await signer.getPublicKey();

		expect(mock.getPubCalls).toBe(1);
		expect(Buffer.from(first)).toEqual(Buffer.from(second));
	});

	it("returns a fresh copy so callers cannot corrupt the cache", async () => {
		const mock = new MockKMS();
		const signer = newSigner(mock);

		const first = await signer.getPublicKey();
		first.fill(0xff);

		const second = await signer.getPublicKey();
		expect(Buffer.from(second)).toEqual(Buffer.from(mock.rawPublicKey()));
	});

	it("propagates KMS errors unchanged", async () => {
		const sentinel = new Error("NotFoundException: key does not exist");
		const mock = new MockKMS();
		mock.getPubHook = () => Promise.reject(sentinel);
		const signer = newSigner(mock);

		await expect(signer.getPublicKey()).rejects.toBe(sentinel);
	});

	it("does not cache a failed fetch — a later call retries", async () => {
		const mock = new MockKMS();
		let calls = 0;
		const goodDer = mock.publicKey.export({ type: "spki", format: "der" });
		mock.getPubHook = () => {
			calls++;
			if (calls === 1) {
				return Promise.reject(new Error("ThrottlingException"));
			}
			return Promise.resolve({ PublicKey: new Uint8Array(goodDer) });
		};
		const signer = newSigner(mock);

		await expect(signer.getPublicKey()).rejects.toThrow(/ThrottlingException/);
		const got = await signer.getPublicKey();
		expect(Buffer.from(got)).toEqual(Buffer.from(mock.rawPublicKey()));
	});

	it("rejects a non-Ed25519 key", async () => {
		const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
		const rsaDer = new Uint8Array(
			publicKey.export({ type: "spki", format: "der" }),
		);
		const mock = new MockKMS();
		mock.getPubHook = () => Promise.resolve({ PublicKey: rsaDer });
		const signer = newSigner(mock);

		await expect(signer.getPublicKey()).rejects.toThrow(/not Ed25519/);
	});

	it("fetches the public key exactly once under concurrent calls", async () => {
		const mock = new MockKMS();
		const signer = newSigner(mock);

		const results = await Promise.all(
			Array.from({ length: 50 }, () => signer.getPublicKey()),
		);

		expect(mock.getPubCalls).toBe(1);
		const expected = Buffer.from(mock.rawPublicKey());
		for (const r of results) {
			expect(Buffer.from(r)).toEqual(expected);
		}
	});
});
