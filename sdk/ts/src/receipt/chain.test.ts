import { describe, expect, it } from "vitest";
import { makeUnsigned } from "../test-utils/receipts.js";
import { verifyChain } from "./chain.js";
import { createReceipt } from "./create.js";
import { canonicalize, hashReceipt, sha256 } from "./hash.js";
import { generateKeyPair, signReceipt } from "./signing.js";

function buildChain(count: number, privateKey: string) {
	const receipts = [];
	let previousHash: string | null = null;

	for (let i = 1; i <= count; i++) {
		const unsigned = makeUnsigned(i, previousHash);
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
		receipts.push(signed);
		previousHash = hashReceipt(signed);
	}

	return receipts;
}

function buildTerminalChain(count: number, privateKey: string) {
	const chain = buildChain(count - 1, privateKey);
	const lastReceipt = chain.at(-1);
	const prevHash = lastReceipt != null ? hashReceipt(lastReceipt) : null;
	const unsigned = createReceipt({
		issuer: { id: "did:agent:test" },
		principal: { id: "did:user:test" },
		action: { type: "filesystem.file.read", risk_level: "low" },
		outcome: { status: "success" },
		chain: {
			sequence: count,
			previous_receipt_hash: prevHash,
			chain_id: "chain_test",
		},
		terminal: true,
	});
	const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");
	return [...chain, signed];
}

describe("verifyChain", () => {
	it("returns valid for an empty chain", () => {
		const { publicKey } = generateKeyPair();
		const result = verifyChain([], publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(0);
		expect(result.brokenAt).toBe(-1);
	});

	it("verifies a single receipt", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(1, privateKey);
		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(1);
		expect(result.receipts[0]?.signatureValid).toBe(true);
		expect(result.receipts[0]?.hashLinkValid).toBe(true);
		expect(result.receipts[0]?.sequenceValid).toBe(true);
	});

	it("verifies a valid 3-receipt chain", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);
		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(3);
		expect(result.brokenAt).toBe(-1);

		for (const r of result.receipts) {
			expect(r.signatureValid).toBe(true);
			expect(r.hashLinkValid).toBe(true);
			expect(r.sequenceValid).toBe(true);
		}
	});

	it("detects a tampered receipt (broken signature)", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);

		// Tamper with the second receipt
		const tampered = chain[1];
		if (tampered) tampered.credentialSubject.action.risk_level = "critical";

		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(1);
		expect(result.receipts[0]?.signatureValid).toBe(true);
		expect(result.receipts[1]?.signatureValid).toBe(false);
	});

	it("detects a broken hash link", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);

		// Replace the second receipt with one that has wrong previous_hash
		const badUnsigned = makeUnsigned(2, "sha256:wrong");
		chain[1] = signReceipt(badUnsigned, privateKey, "did:agent:test#key-1");

		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(1);
		expect(result.receipts[1]?.hashLinkValid).toBe(false);
	});

	it("surfaces hashReceipt errors via the error field", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(2, privateKey);

		// Inject a non-finite number into a canonicalized field. RFC 8785 §3.2.2.3
		// (and hashReceipt -> canonicalize) rejects NaN. chain_id is typed string,
		// so cast through unknown to bypass at runtime.
		const first = chain[0];
		if (first) {
			(
				first.credentialSubject.chain as unknown as { chain_id: number }
			).chain_id = Number.NaN;
		}

		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(1);
		expect(result.error).toMatch(/^hash compute failed at index 0:/);
		expect(result.receipts[1]?.hashLinkValid).toBe(false);
	});

	it("detects a broken sequence", () => {
		const { publicKey, privateKey } = generateKeyPair();

		// Build chain with gap: sequence 1, 3
		const first = signReceipt(
			makeUnsigned(1, null),
			privateKey,
			"did:agent:test#key-1",
		);
		const firstHash = hashReceipt(first);
		const second = signReceipt(
			makeUnsigned(3, firstHash),
			privateKey,
			"did:agent:test#key-1",
		);

		const result = verifyChain([first, second], publicKey);

		expect(result.valid).toBe(false);
		expect(result.receipts[1]?.sequenceValid).toBe(false);
	});

	it("detects wrong signing key", () => {
		const signer = generateKeyPair();
		const other = generateKeyPair();
		const chain = buildChain(2, signer.privateKey);

		const result = verifyChain(chain, other.publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBe(0);
		expect(result.receipts[0]?.signatureValid).toBe(false);
	});

	it("first receipt must have null previous_receipt_hash", () => {
		const { publicKey, privateKey } = generateKeyPair();

		const bad = signReceipt(
			makeUnsigned(1, "sha256:unexpected"),
			privateKey,
			"did:agent:test#key-1",
		);

		const result = verifyChain([bad], publicKey);

		expect(result.valid).toBe(false);
		expect(result.receipts[0]?.hashLinkValid).toBe(false);
	});

	it("continues verifying after a break", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);

		// Tamper with second receipt
		const tampered = chain[1];
		if (tampered) tampered.credentialSubject.action.risk_level = "critical";

		const result = verifyChain(chain, publicKey);

		// Should still have results for all 3 receipts
		expect(result.receipts).toHaveLength(3);
		expect(result.brokenAt).toBe(1);

		// Tampered receipt: signature invalid, but hash link to first is still valid
		expect(result.receipts[1]?.signatureValid).toBe(false);
		expect(result.receipts[1]?.hashLinkValid).toBe(true);

		// Third receipt: own signature valid, but hash link to tampered second is broken
		expect(result.receipts[2]?.signatureValid).toBe(true);
		expect(result.receipts[2]?.hashLinkValid).toBe(false);
	});

	// --- ADR-0008 tests ---

	it("truncated chain is valid without expected options (pinned behaviour, spec §7.3.1)", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(5, privateKey);
		const truncated = chain.slice(0, 3);

		const result = verifyChain(truncated, publicKey);

		expect(result.valid).toBe(true);
		expect(result.length).toBe(3);
	});

	it("expectedLength detects truncation", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(5, privateKey);
		const truncated = chain.slice(0, 3);

		const result = verifyChain(truncated, publicKey, { expectedLength: 5 });

		expect(result.valid).toBe(false);
	});

	it("expectedLength passes when chain matches", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(5, privateKey);

		const result = verifyChain(chain, publicKey, { expectedLength: 5 });

		expect(result.valid).toBe(true);
	});

	it("expectedFinalHash detects truncation", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(5, privateKey);
		const last = chain.at(-1);
		const realFinalHash = last != null ? hashReceipt(last) : "";
		const truncated = chain.slice(0, 3);

		const result = verifyChain(truncated, publicKey, {
			expectedFinalHash: realFinalHash,
		});

		expect(result.valid).toBe(false);
	});

	it("expectedFinalHash passes when chain matches", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(5, privateKey);
		const last = chain.at(-1);
		const finalHash = last != null ? hashReceipt(last) : "";

		const result = verifyChain(chain, publicKey, {
			expectedFinalHash: finalHash,
		});

		expect(result.valid).toBe(true);
	});

	it("terminal chain round-trips as valid", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildTerminalChain(3, privateKey);

		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(true);
		expect(chain.at(-1)?.credentialSubject.chain.terminal).toBe(true);
	});

	it("receipt after terminal is always invalid", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const terminalChain = buildTerminalChain(3, privateKey);
		const terminalReceipt = terminalChain.at(-1);
		const terminalHash =
			terminalReceipt != null ? hashReceipt(terminalReceipt) : "";

		// Append a receipt after the terminal one — protocol violation.
		const extra = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 4,
				previous_receipt_hash: terminalHash,
				chain_id: "chain_test",
			},
		});
		const extraSigned = signReceipt(extra, privateKey, "did:agent:test#key-1");
		const bad = [...terminalChain, extraSigned];

		const result = verifyChain(bad, publicKey);

		expect(result.valid).toBe(false);
		expect(result.brokenAt).toBeGreaterThan(-1);
	});

	it("receipt after terminal fires unconditionally (no caller options needed)", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const terminalChain = buildTerminalChain(2, privateKey);
		const terminalReceipt = terminalChain.at(-1);
		const terminalHash =
			terminalReceipt != null ? hashReceipt(terminalReceipt) : "";

		const extra = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 3,
				previous_receipt_hash: terminalHash,
				chain_id: "chain_test",
			},
		});
		const extraSigned = signReceipt(extra, privateKey, "did:agent:test#key-1");

		const result = verifyChain([...terminalChain, extraSigned], publicKey);

		expect(result.valid).toBe(false);
	});

	it("requireTerminal passes when chain ends in terminal", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildTerminalChain(3, privateKey);

		const result = verifyChain(chain, publicKey, { requireTerminal: true });

		expect(result.valid).toBe(true);
	});

	it("requireTerminal fails when terminal receipt was dropped", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildTerminalChain(3, privateKey);
		const truncated = chain.slice(0, 2); // drop terminal receipt

		const result = verifyChain(truncated, publicKey, { requireTerminal: true });

		expect(result.valid).toBe(false);
	});

	it("requireTerminal not set — non-terminal chain is valid", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(3, privateKey);

		const result = verifyChain(chain, publicKey); // no options

		expect(result.valid).toBe(true);
	});

	it("response_hash note is set when receipt has hash but no body supplied", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "data.api.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_test",
			},
			responseBody: { result: "ok" },
		});
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");

		const result = verifyChain([signed], publicKey);

		expect(result.valid).toBe(true);
		expect(result.responseHashNote).toBeTruthy();
	});

	it("no response_hash note when response_hash absent", () => {
		const { publicKey, privateKey } = generateKeyPair();
		const chain = buildChain(1, privateKey);

		const result = verifyChain(chain, publicKey);

		expect(result.valid).toBe(true);
		expect(result.responseHashNote).toBeFalsy();
	});

	it("createReceipt computes correct response_hash", () => {
		const responseBody = { result: "ok", status: 200 };
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "data.api.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_test",
			},
			responseBody,
		});

		const expected = sha256(canonicalize(responseBody));
		expect(unsigned.credentialSubject.outcome.response_hash).toBe(expected);
	});

	it("redact-then-hash ordering: hash must equal hash(redacted), not hash(raw)", () => {
		const rawResponse = { result: "ok", password: "super-secret" };
		const redactedResponse = { result: "ok", password: "[REDACTED]" };

		const hashOfRedacted = sha256(canonicalize(redactedResponse));
		const hashOfRaw = sha256(canonicalize(rawResponse));
		expect(hashOfRedacted).not.toBe(hashOfRaw);

		// Caller pre-redacts and passes redacted body.
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "data.api.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_test",
			},
			responseBody: redactedResponse,
		});

		expect(unsigned.credentialSubject.outcome.response_hash).toBe(
			hashOfRedacted,
		);
		expect(unsigned.credentialSubject.outcome.response_hash).not.toBe(
			hashOfRaw,
		);
	});

	it("no terminal option — terminal field is absent", () => {
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_test",
			},
			// terminal not set
		});

		expect(unsigned.credentialSubject.chain.terminal).toBeUndefined();
	});

	it("terminal: true emits terminal field", () => {
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "filesystem.file.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_test",
			},
			terminal: true,
		});

		expect(unsigned.credentialSubject.chain.terminal).toBe(true);
	});

	it("responseBodies: matching body passes verification and sets no note", () => {
		const { privateKey, publicKey } = generateKeyPair();
		const body = { result: "ok", status: 200 };
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "data.api.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: { sequence: 1, previous_receipt_hash: null, chain_id: "chain-rb" },
			responseBody: body,
		});
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");

		const result = verifyChain([signed], publicKey, {
			responseBodies: { [signed.id]: body },
		});

		expect(result.valid).toBe(true);
		expect(result.responseHashNote).toBeUndefined();
	});

	it("responseBodies: mismatched body fails verification with error", () => {
		const { privateKey, publicKey } = generateKeyPair();
		const goodBody = { result: "ok" };
		const badBody = { result: "tampered" };
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "data.api.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: { sequence: 1, previous_receipt_hash: null, chain_id: "chain-mm" },
			responseBody: goodBody,
		});
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");

		const result = verifyChain([signed], publicKey, {
			responseBodies: { [signed.id]: badBody },
		});

		expect(result.valid).toBe(false);
		expect(result.error).toMatch(/response_hash mismatch/);
	});

	it("responseBodies: absent entry emits note but does not fail", () => {
		const { privateKey, publicKey } = generateKeyPair();
		const unsigned = createReceipt({
			issuer: { id: "did:agent:test" },
			principal: { id: "did:user:test" },
			action: { type: "data.api.read", risk_level: "low" },
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain-absent",
			},
			responseBody: { result: "ok" },
		});
		const signed = signReceipt(unsigned, privateKey, "did:agent:test#key-1");

		// responseBodies supplied but no entry for this receipt id.
		const result = verifyChain([signed], publicKey, {
			responseBodies: {},
		});

		expect(result.valid).toBe(true);
		expect(result.responseHashNote).toBeTruthy();
	});
});
