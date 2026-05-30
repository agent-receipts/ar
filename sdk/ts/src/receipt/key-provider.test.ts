import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	GeneratingKeyProvider,
	ProductionKeyProviderError,
} from "./key-provider.js";
import { signReceipt, verifyReceipt } from "./signing.js";
import type { UnsignedAgentReceipt } from "./types.js";
import { CONTEXT, CREDENTIAL_TYPE, VERSION } from "./types.js";

const ENV_VAR = "AGENTRECEIPTS_PRODUCTION";

function makeUnsignedReceipt(): UnsignedAgentReceipt {
	return {
		"@context": CONTEXT,
		id: "urn:receipt:550e8400-e29b-41d4-a716-446655440000",
		type: CREDENTIAL_TYPE,
		version: VERSION,
		issuer: { id: "did:agent:test-agent" },
		issuanceDate: "2026-03-29T14:31:00Z",
		credentialSubject: {
			principal: { id: "did:user:test-user" },
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
	};
}

describe("GeneratingKeyProvider", () => {
	const original = process.env[ENV_VAR];
	let stderr: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		// Keep the suite quiet: the dev-only warning writes to real stderr.
		stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
		delete process.env[ENV_VAR];
	});

	afterEach(() => {
		stderr.mockRestore();
		if (original === undefined) {
			delete process.env[ENV_VAR];
		} else {
			process.env[ENV_VAR] = original;
		}
	});

	it("throws ProductionKeyProviderError when AGENTRECEIPTS_PRODUCTION=true", () => {
		process.env[ENV_VAR] = "true";
		expect(() => new GeneratingKeyProvider()).toThrow(
			ProductionKeyProviderError,
		);
	});

	it("does not emit a warning when the production guard fires", () => {
		process.env[ENV_VAR] = "true";
		expect(() => new GeneratingKeyProvider()).toThrow();
		expect(stderr).not.toHaveBeenCalled();
	});

	it('only treats the exact value "true" as production', () => {
		process.env[ENV_VAR] = "1";
		expect(() => new GeneratingKeyProvider()).not.toThrow();
	});

	it("generates a usable, stable keypair outside production", async () => {
		const provider = new GeneratingKeyProvider();
		const kp = await provider.getKeyPair();

		expect(kp.publicKey).toContain("BEGIN PUBLIC KEY");
		expect(kp.privateKey).toContain("BEGIN PRIVATE KEY");

		// Stable for the lifetime of the provider.
		expect(await provider.getKeyPair()).toEqual(kp);
	});

	it("signs and verifies a receipt with the generated keypair", async () => {
		const provider = new GeneratingKeyProvider();
		const kp = await provider.getKeyPair();
		const unsigned = makeUnsignedReceipt();

		const signed = signReceipt(unsigned, kp.privateKey, "did:agent:test#key-1");
		expect(verifyReceipt(signed, kp.publicKey)).toBe(true);
	});

	it("emits exactly one stderr warning per process", async () => {
		// Fresh module so the once-per-process latch starts unset. The
		// beforeEach `stderr` spy already covers process.stderr (a global
		// singleton), so it captures writes from the re-imported module too.
		vi.resetModules();
		const { GeneratingKeyProvider: FreshProvider } = await import(
			"./key-provider.js"
		);

		new FreshProvider();
		new FreshProvider();
		new FreshProvider();

		const warnings = stderr.mock.calls.filter(([chunk]) =>
			String(chunk).includes("GeneratingKeyProvider is dev-only"),
		);
		expect(warnings).toHaveLength(1);
	});

	it("exports a named error class", () => {
		const err = new ProductionKeyProviderError();
		expect(err.name).toBe("ProductionKeyProviderError");
		expect(err).toBeInstanceOf(Error);
	});
});
