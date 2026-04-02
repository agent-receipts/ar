import { describe, expect, it } from "vitest";
import {
	type AgentReceipt,
	CONTEXT,
	CREDENTIAL_TYPE,
	type UnsignedAgentReceipt,
	VERSION,
} from "./types.js";

describe("receipt schema constants", () => {
	it("has the correct context URIs", () => {
		expect(CONTEXT).toEqual([
			"https://www.w3.org/ns/credentials/v2",
			"https://attest.sh/v1",
		]);
	});

	it("has the correct credential type", () => {
		expect(CREDENTIAL_TYPE).toEqual(["VerifiableCredential", "AgentReceipt"]);
	});

	it("has version 0.1.0", () => {
		expect(VERSION).toBe("0.1.0");
	});
});

describe("receipt types", () => {
	it("accepts a minimal receipt", () => {
		const receipt: AgentReceipt = {
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
			proof: { type: "Ed25519Signature2020", proofValue: "z..." },
		};

		expect(receipt.id).toBe("urn:receipt:550e8400-e29b-41d4-a716-446655440000");
		expect(receipt.credentialSubject.action.risk_level).toBe("low");
	});

	it("accepts a full receipt with all optional fields", () => {
		const receipt: AgentReceipt = {
			"@context": CONTEXT,
			id: "urn:receipt:550e8400-e29b-41d4-a716-446655440000",
			type: CREDENTIAL_TYPE,
			version: VERSION,
			issuer: {
				id: "did:agent:claude-cowork-instance-abc123",
				type: "AIAgent",
				name: "Claude Cowork",
				operator: { id: "did:org:anthropic", name: "Anthropic" },
				model: "claude-sonnet-4.6",
				session_id: "session_xyz789",
			},
			issuanceDate: "2026-03-29T14:30:00Z",
			credentialSubject: {
				principal: { id: "did:user:otto-abc", type: "HumanPrincipal" },
				action: {
					id: "act_001",
					type: "communication.email.send",
					risk_level: "high",
					target: { system: "mail.google.com", resource: "email:compose" },
					parameters_hash: "sha256:abc123",
					timestamp: "2026-03-29T14:30:00Z",
					trusted_timestamp: null,
				},
				intent: {
					conversation_hash: "sha256:def456",
					prompt_preview: "Send the Q3 report to the team",
					prompt_preview_truncated: true,
					reasoning_hash: "sha256:ghi789",
				},
				outcome: {
					status: "success",
					error: null,
					reversible: true,
					reversal_method: "gmail:undo_send",
					reversal_window_seconds: 30,
					state_change: {
						before_hash: "sha256:before",
						after_hash: "sha256:after",
					},
				},
				authorization: {
					scopes: ["email:send", "drive:read"],
					granted_at: "2026-03-29T14:00:00Z",
					expires_at: "2026-03-29T15:00:00Z",
					grant_ref: null,
				},
				chain: {
					sequence: 1,
					previous_receipt_hash: null,
					chain_id: "chain_session_xyz789",
				},
			},
			proof: {
				type: "Ed25519Signature2020",
				created: "2026-03-29T14:30:01Z",
				verificationMethod: "did:agent:claude-cowork-instance-abc123#key-1",
				proofPurpose: "assertionMethod",
				proofValue: "z...",
			},
		};

		expect(receipt.credentialSubject.intent?.prompt_preview).toBe(
			"Send the Q3 report to the team",
		);
		expect(receipt.credentialSubject.authorization?.scopes).toEqual([
			"email:send",
			"drive:read",
		]);
	});

	it("UnsignedAgentReceipt omits proof", () => {
		const unsigned: UnsignedAgentReceipt = {
			"@context": CONTEXT,
			id: "urn:receipt:test",
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
		};

		expect(unsigned).not.toHaveProperty("proof");
	});
});
