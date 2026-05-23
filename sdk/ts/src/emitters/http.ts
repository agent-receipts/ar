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
 *     never thrown to the caller. Background deliveries are tracked in a
 *     pending set so callers can {@link HttpEmitter.drain} before process
 *     exit to avoid losing in-flight receipts.
 *
 * mTLS uses an `undici.Agent` with the supplied cert/key bytes. Node's
 * global `fetch` is undici-based and accepts the `dispatcher` option;
 * the older `node:https.Agent` / `init.agent` style is ignored by
 * `globalThis.fetch` and therefore unsuitable here.
 *
 * !!! FIRE-AND-FORGET CRASH-LOSS RISK !!!
 * In `"fire-and-forget"` mode the background delivery promise may not
 * have settled before the process exits, in which case the receipt is
 * lost on the wire. Call {@link HttpEmitter.drain} on shutdown when you
 * need at-least-once delivery semantics from this mode.
 */

import { Agent } from "undici";
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
	// Undici dispatcher used for mTLS. Typed as `unknown` because `fetch`'s
	// `init` is the Web Fetch shape and doesn't surface `dispatcher` — we
	// pass it through a tagged cast below.
	private readonly mtlsAgent: unknown;
	private readonly signal: AbortSignal | undefined;
	// Tracks fire-and-forget background deliveries so {@link drain} can
	// await them. Promises remove themselves on settle so the set stays
	// bounded.
	private readonly pending: Set<Promise<void>> = new Set();

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
		this.signal = config.signal;

		if (!this.endpoint.startsWith("https://")) {
			// ADR-0020 requires HTTPS for production. Permit HTTP for tests
			// and dev loopback but warn so misconfigurations don't slip
			// through silently.
			this.debugLog("HttpEmitter: endpoint is not https://", {
				endpoint: this.endpoint,
			});
			// Always warn via the platform logger too — debugLog defaults to
			// a no-op, which would hide the issue from production callers.
			console.warn(
				`HttpEmitter: endpoint ${this.endpoint} is not HTTPS; receipts will travel unencrypted`,
			);
		}

		if (this.auth.type === "mtls") {
			// undici.Agent reads PEM bytes directly — no on-disk tempfile
			// needed. Buffers are accepted as cert/key inputs.
			this.mtlsAgent = new Agent({
				connect: {
					cert: Buffer.from(this.auth.cert),
					key: Buffer.from(this.auth.key),
				},
			});
		} else {
			this.mtlsAgent = undefined;
		}
	}

	async emit(receipt: AgentReceipt): Promise<void> {
		if (this.strategy === "fire-and-forget") {
			// Schedule and return immediately. Errors are swallowed because the
			// caller explicitly opted into the no-guarantee mode. Track the
			// promise so {@link drain} can wait for it.
			const task = this.deliver(receipt).catch((err: unknown) => {
				this.debugLog("HttpEmitter dropped receipt (fire-and-forget)", {
					endpoint: this.endpoint,
					err: errorMessage(err),
				});
			});
			this.pending.add(task);
			task.finally(() => {
				this.pending.delete(task);
			});
			return;
		}
		await this.deliver(receipt);
	}

	/**
	 * Wait for every fire-and-forget background delivery scheduled so far
	 * to settle. Call this on graceful shutdown to give in-flight receipts
	 * a chance to land before the process exits. Returns immediately when
	 * there are no pending operations.
	 */
	async drain(): Promise<void> {
		// Snapshot — callers may emit during drain; those new promises join
		// the next drain cycle, not this one.
		const snapshot = Array.from(this.pending);
		await Promise.allSettled(snapshot);
	}

	private async deliver(receipt: AgentReceipt): Promise<void> {
		const body = JSON.stringify(receipt);
		let lastError: unknown;
		let lastStatus: number | undefined;

		for (let attempt = 1; attempt <= this.retry.maxAttempts; attempt++) {
			if (this.signal?.aborted) {
				throw new EmitError(
					`HttpEmitter: cancelled before attempt ${attempt} to ${this.endpoint}`,
					{ cause: this.signal.reason },
				);
			}
			let response: Response;
			try {
				response = await this.doFetch(body);
			} catch (err) {
				lastError = err;
				lastStatus = undefined;
				if (attempt >= this.retry.maxAttempts) {
					break;
				}
				try {
					await sleep(this.backoffDelay(attempt), this.signal);
				} catch (waitErr) {
					throw new EmitError(
						`HttpEmitter: cancelled while waiting to retry ${this.endpoint}`,
						{ cause: waitErr },
					);
				}
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
				try {
					await sleep(this.backoffDelay(attempt), this.signal);
				} catch (waitErr) {
					throw new EmitError(
						`HttpEmitter: cancelled while waiting to retry ${this.endpoint}`,
						{ cause: waitErr },
					);
				}
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
		// Keep the event loop free to exit while we're waiting on the
		// upstream response — the abort path will still fire.
		(timer as { unref?: () => void }).unref?.();
		try {
			const headers: Record<string, string> = {
				"Content-Type": "application/ld+json",
			};
			if (this.auth.type === "api-key") {
				headers[this.auth.header] = this.auth.value;
			} else if (this.auth.type === "bearer") {
				headers.Authorization = `Bearer ${this.auth.token}`;
			}

			// `dispatcher` is the undici-specific knob that Node's global
			// fetch honours for plumbing a custom Agent through. The Web
			// Fetch types don't expose it (the augmentation undici ships
			// applies only when @types/node sees undici), so we forward via
			// a Record and let undici read its field. Non-undici fetch
			// implementations (browser polyfills) ignore unknown init
			// fields — mTLS is Node-only by design.
			const init: Record<string, unknown> = {
				method: "POST",
				headers,
				body,
				signal: controller.signal,
			};
			if (this.mtlsAgent !== undefined) {
				init.dispatcher = this.mtlsAgent;
			}

			return await this.fetchImpl(this.endpoint, init as RequestInit);
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

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	if (signal?.aborted) {
		return Promise.reject(signal.reason ?? new Error("aborted"));
	}
	return new Promise<void>((resolve, reject) => {
		const t = setTimeout(() => {
			signal?.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		// Don't keep the event loop alive on a sleeping retry.
		(t as { unref?: () => void }).unref?.();
		const onAbort = (): void => {
			clearTimeout(t);
			reject(signal?.reason ?? new Error("aborted"));
		};
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

function errorMessage(err: unknown): string {
	if (err instanceof Error) {
		return err.message;
	}
	return String(err);
}
