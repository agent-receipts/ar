/**
 * HttpEmitter — POSTs signed receipts to a collector endpoint over HTTP(S).
 *
 * Wire contract (per ADR-0020 §"Collector contract"):
 *   POST <endpoint>
 *   Content-Type: application/ld+json
 *   Body: JSON-serialised AgentReceipt
 *
 *   201 Created    -> resolve
 *   409 Conflict   -> resolve (duplicate id is idempotent re-delivery)
 *   400 Bad Request-> throw EmitError immediately (no retry)
 *   5xx / network  -> retry with exponential backoff + jitter
 *
 * Strategy:
 *   - "sync" (default): emit() awaits the collector ack and respects the
 *     full retry budget.
 *   - "fire-and-forget": emit() schedules the POST and resolves
 *     immediately; the background promise's error is logged at debug and
 *     never thrown to the caller.
 *
 * mTLS uses a Node `https.Agent` built from the supplied cert/key
 * buffers; falls back to global agent for the other auth variants.
 */

import { Agent } from "node:https";
import type { AgentReceipt } from "../receipt/types.js";
import {
	EmitError,
	type Emitter,
	type HttpEmitterAuth,
	type HttpEmitterConfig,
	type RetryConfig,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_DELAY_MS = 100;
const DEFAULT_MAX_DELAY_MS = 10_000;

/** No-op debug logger used when the caller does not supply one. */
const NOOP_LOG = (
	_message: string,
	_attrs: Record<string, unknown>,
): void => {};

export class HttpEmitter implements Emitter {
	private readonly endpoint: string;
	private readonly auth: HttpEmitterAuth;
	private readonly strategy: "sync" | "fire-and-forget";
	private readonly retry: Required<RetryConfig>;
	private readonly timeoutMs: number;
	private readonly debugLog: (
		message: string,
		attrs: Record<string, unknown>,
	) => void;
	private readonly fetchImpl: typeof fetch;
	// Lazily-built mTLS agent — node:https types are platform-only; treat as
	// `unknown` here so the module continues to compile under non-Node fetch
	// implementations even though we only ever construct it under Node.
	private readonly mtlsAgent: unknown;

	constructor(config: HttpEmitterConfig) {
		if (!config.endpoint) {
			throw new Error("HttpEmitter: endpoint is required");
		}
		this.endpoint = config.endpoint;
		this.auth = config.auth ?? { type: "none" };
		this.strategy = config.strategy ?? "sync";
		this.retry = {
			maxAttempts: config.retry?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
			baseDelayMs: config.retry?.baseDelayMs ?? DEFAULT_BASE_DELAY_MS,
			maxDelayMs: config.retry?.maxDelayMs ?? DEFAULT_MAX_DELAY_MS,
		};
		this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		this.debugLog = config.debugLog ?? NOOP_LOG;
		this.fetchImpl = config.fetch ?? fetch;

		if (this.auth.type === "mtls") {
			this.mtlsAgent = new Agent({
				cert: Buffer.from(this.auth.cert),
				key: Buffer.from(this.auth.key),
			});
		} else {
			this.mtlsAgent = undefined;
		}
	}

	async emit(receipt: AgentReceipt): Promise<void> {
		if (this.strategy === "fire-and-forget") {
			// Schedule and return immediately. Errors are swallowed because the
			// caller explicitly opted into the no-guarantee mode.
			void this.deliver(receipt).catch((err: unknown) => {
				this.debugLog("HttpEmitter dropped receipt (fire-and-forget)", {
					endpoint: this.endpoint,
					err: errorMessage(err),
				});
			});
			return;
		}
		await this.deliver(receipt);
	}

	private async deliver(receipt: AgentReceipt): Promise<void> {
		const body = JSON.stringify(receipt);
		let lastError: unknown;
		let lastStatus: number | undefined;

		for (let attempt = 1; attempt <= this.retry.maxAttempts; attempt++) {
			let response: Response;
			try {
				response = await this.doFetch(body);
			} catch (err) {
				lastError = err;
				lastStatus = undefined;
				if (attempt >= this.retry.maxAttempts) {
					break;
				}
				await sleep(this.backoffDelay(attempt));
				continue;
			}

			if (response.status === 201 || response.status === 409) {
				return;
			}
			if (response.status === 400) {
				throw new EmitError(
					`HttpEmitter: 400 Bad Request from ${this.endpoint}`,
					{ status: 400 },
				);
			}
			if (response.status >= 500 && response.status < 600) {
				lastError = new Error(`HTTP ${response.status}`);
				lastStatus = response.status;
				if (attempt >= this.retry.maxAttempts) {
					break;
				}
				await sleep(this.backoffDelay(attempt));
				continue;
			}
			// Any other status (e.g. 401, 403, 404, 4xx that isn't 400/409) is
			// non-retryable — the request shape is wrong for this endpoint and
			// retrying would just waste the budget.
			throw new EmitError(
				`HttpEmitter: unexpected HTTP ${response.status} from ${this.endpoint}`,
				{ status: response.status },
			);
		}

		throw new EmitError(
			`HttpEmitter: ${this.retry.maxAttempts} attempts exhausted for ${this.endpoint}`,
			{ status: lastStatus, cause: lastError },
		);
	}

	private async doFetch(body: string): Promise<Response> {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const headers: Record<string, string> = {
				"Content-Type": "application/ld+json",
			};
			if (this.auth.type === "api-key") {
				headers[this.auth.header] = this.auth.value;
			} else if (this.auth.type === "bearer") {
				headers.Authorization = `Bearer ${this.auth.token}`;
			}

			// `dispatcher` is the undici-style option used by Node's global
			// fetch to plumb a custom agent through. Cast to a loose record so
			// non-Node fetch implementations (which ignore the field) still
			// type-check.
			const init: RequestInit & { dispatcher?: unknown; agent?: unknown } = {
				method: "POST",
				headers,
				body,
				signal: controller.signal,
			};
			if (this.mtlsAgent !== undefined) {
				init.agent = this.mtlsAgent;
			}

			return await this.fetchImpl(this.endpoint, init);
		} finally {
			clearTimeout(timer);
		}
	}

	/**
	 * Exponential backoff with full jitter: delay = random(0, min(max,
	 * base * 2^(attempt-1))). Following AWS Architecture Blog
	 * recommendations for retry storms.
	 */
	private backoffDelay(attempt: number): number {
		const exp = Math.min(
			this.retry.maxDelayMs,
			this.retry.baseDelayMs * 2 ** (attempt - 1),
		);
		return Math.floor(Math.random() * exp);
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => {
		const t = setTimeout(resolve, ms);
		// Don't keep the event loop alive on a sleeping retry.
		(t as { unref?: () => void }).unref?.();
	});
}

function errorMessage(err: unknown): string {
	if (err instanceof Error) {
		return err.message;
	}
	return String(err);
}
