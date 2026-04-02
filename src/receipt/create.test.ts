import { describe, expect, it } from "vitest";
import type { CreateReceiptInput } from "./create.js";
import { createReceipt } from "./create.js";
import { CONTEXT, CREDENTIAL_TYPE, VERSION } from "./types.js";

function makeInput(
	overrides?: Partial<CreateReceiptInput>,
): CreateReceiptInput {
	return {
		issuer: { id: "did:agent:test-agent" },
		principal: { id: "did:user:test-user" },
		action: {
			type: "filesystem.file.read",
			risk_level: "low",
		},
		outcome: { status: "success" },
		chain: {
			sequence: 1,
			previous_receipt_hash: null,
			chain_id: "chain_test",
		},
		...overrides,
	};
}

describe("createReceipt", () => {
	it("sets context, type, and version constants", () => {
		const receipt = createReceipt(makeInput());

		expect(receipt["@context"]).toEqual(CONTEXT);
		expect(receipt.type).toEqual(CREDENTIAL_TYPE);
		expect(receipt.version).toBe(VERSION);
	});

	it("generates a URN UUID for the receipt id", () => {
		const receipt = createReceipt(makeInput());

		expect(receipt.id).toMatch(
			/^urn:receipt:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
		);
	});

	it("generates unique ids on each call", () => {
		const a = createReceipt(makeInput());
		const b = createReceipt(makeInput());

		expect(a.id).not.toBe(b.id);
	});

	it("generates an action id", () => {
		const receipt = createReceipt(makeInput());

		expect(receipt.credentialSubject.action.id).toMatch(
			/^act_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
		);
	});

	it("sets issuanceDate to current time", () => {
		const before = new Date().toISOString();
		const receipt = createReceipt(makeInput());
		const after = new Date().toISOString();

		expect(receipt.issuanceDate >= before).toBe(true);
		expect(receipt.issuanceDate <= after).toBe(true);
	});

	it("defaults action timestamp to now", () => {
		const before = new Date().toISOString();
		const receipt = createReceipt(makeInput());

		expect(receipt.credentialSubject.action.timestamp >= before).toBe(true);
	});

	it("allows overriding action timestamp", () => {
		const receipt = createReceipt(
			makeInput({ actionTimestamp: "2026-01-01T00:00:00Z" }),
		);

		expect(receipt.credentialSubject.action.timestamp).toBe(
			"2026-01-01T00:00:00Z",
		);
	});

	it("passes through issuer, principal, outcome, and chain", () => {
		const input = makeInput();
		const receipt = createReceipt(input);

		expect(receipt.issuer).toEqual(input.issuer);
		expect(receipt.credentialSubject.principal).toEqual(input.principal);
		expect(receipt.credentialSubject.outcome).toEqual(input.outcome);
		expect(receipt.credentialSubject.chain).toEqual(input.chain);
	});

	it("passes through action fields", () => {
		const input = makeInput({
			action: {
				type: "filesystem.file.create",
				risk_level: "medium",
				target: { system: "local", resource: "/tmp/test.txt" },
				parameters_hash: "sha256:abc123",
			},
		});
		const receipt = createReceipt(input);
		const action = receipt.credentialSubject.action;

		expect(action.type).toBe("filesystem.file.create");
		expect(action.risk_level).toBe("medium");
		expect(action.target).toEqual({
			system: "local",
			resource: "/tmp/test.txt",
		});
		expect(action.parameters_hash).toBe("sha256:abc123");
	});

	it("includes intent when provided", () => {
		const receipt = createReceipt(
			makeInput({
				intent: {
					prompt_preview: "Read the config file",
					conversation_hash: "sha256:abc",
				},
			}),
		);

		expect(receipt.credentialSubject.intent).toEqual({
			prompt_preview: "Read the config file",
			conversation_hash: "sha256:abc",
		});
	});

	it("omits intent when not provided", () => {
		const receipt = createReceipt(makeInput());

		expect(receipt.credentialSubject).not.toHaveProperty("intent");
	});

	it("includes authorization when provided", () => {
		const receipt = createReceipt(
			makeInput({
				authorization: {
					scopes: ["filesystem:read"],
					granted_at: "2026-03-29T14:00:00Z",
				},
			}),
		);

		expect(receipt.credentialSubject.authorization).toEqual({
			scopes: ["filesystem:read"],
			granted_at: "2026-03-29T14:00:00Z",
		});
	});

	it("omits authorization when not provided", () => {
		const receipt = createReceipt(makeInput());

		expect(receipt.credentialSubject).not.toHaveProperty("authorization");
	});

	it("does not include a proof field", () => {
		const receipt = createReceipt(makeInput());

		expect(receipt).not.toHaveProperty("proof");
	});
});
