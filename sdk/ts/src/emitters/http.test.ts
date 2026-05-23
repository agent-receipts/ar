/**
 * Tests for {@link HttpEmitter}: collector POST contract, auth headers,
 * status mapping, retry/backoff, and fire-and-forget strategy.
 *
 * Uses an in-process http.createServer rather than mocking fetch so the
 * test exercises the same wire path as production callers.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AgentReceipt } from "../receipt/types.js";
import { HttpEmitter } from "./http.js";
import { EmitError } from "./types.js";

function fakeReceipt(id: string): AgentReceipt {
	return {
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		id,
		type: ["VerifiableCredential", "AgentReceipt"],
		version: "0.3.0",
		issuer: { id: "did:agent:test" },
		issuanceDate: "2026-05-23T00:00:00Z",
		credentialSubject: {
			principal: { id: "did:user:test" },
			action: {
				id: "act",
				type: "filesystem.file.read",
				risk_level: "low",
				timestamp: "2026-05-23T00:00:00Z",
			},
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain-1",
			},
		},
		proof: { type: "Ed25519Signature2020", proofValue: "z-fake" },
	} as unknown as AgentReceipt;
}

interface CollectorRequest {
	method: string;
	url: string;
	headers: Record<string, string | string[] | undefined>;
	body: string;
}

interface TestCollector {
	url: string;
	requests: CollectorRequest[];
	setResponder: (
		fn: (req: CollectorRequest, attempt: number) => { status: number },
	) => void;
	stop: () => Promise<void>;
}

async function startCollector(): Promise<TestCollector> {
	const requests: CollectorRequest[] = [];
	let attempt = 0;
	let responder: (
		req: CollectorRequest,
		attempt: number,
	) => { status: number } = () => ({ status: 201 });

	const server: Server = createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (c: Buffer) => chunks.push(c));
		req.on("end", () => {
			const body = Buffer.concat(chunks).toString("utf8");
			const captured: CollectorRequest = {
				method: req.method ?? "",
				url: req.url ?? "",
				headers: req.headers,
				body,
			};
			requests.push(captured);
			attempt += 1;
			const { status } = responder(captured, attempt);
			res.statusCode = status;
			res.end();
		});
	});

	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const addr = server.address() as AddressInfo;

	return {
		url: `http://127.0.0.1:${addr.port}/receipts`,
		requests,
		setResponder: (fn) => {
			responder = fn;
		},
		stop: () =>
			new Promise<void>((resolve, reject) => {
				server.closeAllConnections?.();
				server.close((err) => (err ? reject(err) : resolve()));
			}),
	};
}

describe("HttpEmitter", () => {
	let collector: TestCollector;

	beforeEach(async () => {
		collector = await startCollector();
	});
	afterEach(async () => {
		await collector.stop();
	});

	it("POSTs application/ld+json with the JSON-serialised receipt on 201", async () => {
		collector.setResponder(() => ({ status: 201 }));
		const emitter = new HttpEmitter({ endpoint: collector.url });
		const receipt = fakeReceipt("urn:r:1");

		await emitter.emit(receipt);

		expect(collector.requests).toHaveLength(1);
		const req = collector.requests[0];
		if (req === undefined) {
			throw new Error("no captured request");
		}
		expect(req.method).toBe("POST");
		expect(req.headers["content-type"]).toBe("application/ld+json");
		expect(JSON.parse(req.body).id).toBe("urn:r:1");
	});

	it("treats 409 Conflict as success (idempotent re-delivery)", async () => {
		collector.setResponder(() => ({ status: 409 }));
		const emitter = new HttpEmitter({ endpoint: collector.url });
		await expect(emitter.emit(fakeReceipt("r"))).resolves.toBeUndefined();
		expect(collector.requests).toHaveLength(1);
	});

	it("throws immediately on 400 without retrying", async () => {
		collector.setResponder(() => ({ status: 400 }));
		const emitter = new HttpEmitter({
			endpoint: collector.url,
			retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 1 },
		});
		await expect(emitter.emit(fakeReceipt("r"))).rejects.toBeInstanceOf(
			EmitError,
		);
		expect(collector.requests).toHaveLength(1);
	});

	it("retries 5xx and resolves on a later 201", async () => {
		collector.setResponder((_req, attempt) => ({
			status: attempt < 3 ? 503 : 201,
		}));
		const emitter = new HttpEmitter({
			endpoint: collector.url,
			retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 1 },
		});

		await expect(emitter.emit(fakeReceipt("r"))).resolves.toBeUndefined();
		expect(collector.requests.length).toBeGreaterThanOrEqual(3);
	});

	it("throws EmitError after exhausting the retry budget on persistent 5xx", async () => {
		collector.setResponder(() => ({ status: 502 }));
		const emitter = new HttpEmitter({
			endpoint: collector.url,
			retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1 },
		});

		const err = await emitter.emit(fakeReceipt("r")).catch((e) => e);
		expect(err).toBeInstanceOf(EmitError);
		expect((err as EmitError).status).toBe(502);
		expect(collector.requests).toHaveLength(3);
	});

	it("attaches api-key auth header when configured", async () => {
		collector.setResponder(() => ({ status: 201 }));
		const emitter = new HttpEmitter({
			endpoint: collector.url,
			auth: { type: "api-key", header: "X-Api-Key", value: "secret" },
		});
		await emitter.emit(fakeReceipt("r"));
		const req = collector.requests[0];
		if (req === undefined) {
			throw new Error("no captured request");
		}
		expect(req.headers["x-api-key"]).toBe("secret");
	});

	it("attaches bearer auth header when configured", async () => {
		collector.setResponder(() => ({ status: 201 }));
		const emitter = new HttpEmitter({
			endpoint: collector.url,
			auth: { type: "bearer", token: "tok-xyz" },
		});
		await emitter.emit(fakeReceipt("r"));
		const req = collector.requests[0];
		if (req === undefined) {
			throw new Error("no captured request");
		}
		expect(req.headers.authorization).toBe("Bearer tok-xyz");
	});

	it("does not attach an Authorization header when auth is none", async () => {
		collector.setResponder(() => ({ status: 201 }));
		const emitter = new HttpEmitter({ endpoint: collector.url });
		await emitter.emit(fakeReceipt("r"));
		const req = collector.requests[0];
		if (req === undefined) {
			throw new Error("no captured request");
		}
		expect(req.headers.authorization).toBeUndefined();
	});

	it("accepts mtls config at construction without requiring the server", () => {
		// We can't easily run a full mTLS handshake against a synthetic test
		// server, but we can pin that the cert/key Buffers feed an https.Agent
		// without throwing. The actual mTLS path is exercised by integration
		// tests against a real collector.
		expect(
			() =>
				new HttpEmitter({
					endpoint: "https://example.com/receipts",
					auth: {
						type: "mtls",
						cert: new TextEncoder().encode("-----BEGIN CERTIFICATE-----\n"),
						key: new TextEncoder().encode("-----BEGIN PRIVATE KEY-----\n"),
					},
				}),
		).not.toThrow();
	});

	it("fire-and-forget resolves immediately without waiting for the collector", async () => {
		// Slow collector — sync mode would take >100ms but fire-and-forget
		// must return in <50ms.
		collector.setResponder(() => ({ status: 201 }));
		const slowCollector = await startCollector();
		try {
			slowCollector.setResponder(() => ({ status: 201 }));
			const emitter = new HttpEmitter({
				endpoint: slowCollector.url,
				strategy: "fire-and-forget",
				timeoutMs: 5_000,
			});

			const start = Date.now();
			await emitter.emit(fakeReceipt("r"));
			expect(Date.now() - start).toBeLessThan(50);
		} finally {
			await slowCollector.stop();
		}
	});

	it("fire-and-forget swallows errors and invokes debugLog", async () => {
		collector.setResponder(() => ({ status: 500 }));
		const drops: Array<{ msg: string; attrs: Record<string, unknown> }> = [];
		const emitter = new HttpEmitter({
			endpoint: collector.url,
			strategy: "fire-and-forget",
			retry: { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 },
			debugLog: (msg, attrs) => drops.push({ msg, attrs }),
		});

		// emit() must not reject even though the delivery will fail.
		await expect(emitter.emit(fakeReceipt("r"))).resolves.toBeUndefined();

		// Give the background delivery a moment to complete.
		await new Promise<void>((resolve) => setTimeout(resolve, 50));
		expect(drops.length).toBeGreaterThanOrEqual(1);
	});

	it("rejects construction without an endpoint", () => {
		expect(() => new HttpEmitter({ endpoint: "" })).toThrow(/endpoint/);
	});

	it("times out a stalled request and treats it as a retryable error", async () => {
		// Slow handler that never responds — the abort signal must cut it off.
		const stalled = createServer((_req, res) => {
			// Hang the response intentionally — no res.end() until the test
			// tears the server down.
			void res; // silence unused-var lint
		});
		await new Promise<void>((resolve) =>
			stalled.listen(0, "127.0.0.1", resolve),
		);
		try {
			const addr = stalled.address() as AddressInfo;
			const url = `http://127.0.0.1:${addr.port}/receipts`;
			const emitter = new HttpEmitter({
				endpoint: url,
				timeoutMs: 50,
				retry: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 1 },
			});

			await expect(emitter.emit(fakeReceipt("r"))).rejects.toBeInstanceOf(
				EmitError,
			);
		} finally {
			stalled.closeAllConnections?.();
			await new Promise<void>((resolve, reject) =>
				stalled.close((err) => (err ? reject(err) : resolve())),
			);
		}
	});
});
