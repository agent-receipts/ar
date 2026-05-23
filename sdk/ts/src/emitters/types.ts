/**
 * Emitter abstraction for delivering signed agent receipts.
 *
 * Per ADR-0020, an Emitter is responsible only for delivery of a
 * fully-signed, already-chained {@link AgentReceipt}. Construction,
 * signing, and chaining stay client-side and upstream of this layer.
 *
 * The {@link DaemonEmitter} in `../daemon-emitter.js` is a separate legacy
 * adapter that takes unsigned tool-call frames; it does NOT implement
 * this interface (see ADR-0020 §"Migration from the current daemon
 * architecture" — step 2 is tracked separately).
 */

import type { AgentReceipt } from "../receipt/types.js";

/**
 * Delivers a signed {@link AgentReceipt}. Implementations are responsible
 * for transport (HTTPS, in-memory, composite, buffered) but never for
 * construction, signing, or chaining.
 *
 * @see {@link HttpEmitter} for the production transport.
 * @see {@link InMemoryEmitter} for the test double.
 */
export interface Emitter {
	emit(receipt: AgentReceipt): Promise<void>;
}

/**
 * Error thrown when an {@link Emitter}'s retry budget is exhausted (or a
 * non-retryable status is returned). Wraps the last underlying transport
 * error and exposes the HTTP status code when one is available.
 */
export class EmitError extends Error {
	readonly status?: number;
	readonly cause?: unknown;

	constructor(
		message: string,
		options: { status?: number; cause?: unknown } = {},
	) {
		super(message);
		this.name = "EmitError";
		this.status = options.status;
		this.cause = options.cause;
	}
}

/** Authentication variants supported by {@link HttpEmitter}. */
export type HttpEmitterAuth =
	| { type: "api-key"; header: string; value: string }
	| { type: "bearer"; token: string }
	| { type: "mtls"; cert: Uint8Array; key: Uint8Array }
	| { type: "none" };

/**
 * Exponential-backoff retry policy used by {@link HttpEmitter} on 5xx and
 * network errors. Fixed budget; `maxAttempts` includes the first attempt.
 */
export interface RetryConfig {
	/** Total attempts including the first. Defaults to 5. */
	maxAttempts?: number;
	/** Base delay in milliseconds for exponential backoff. Defaults to 100ms. */
	baseDelayMs?: number;
	/** Maximum per-attempt delay in milliseconds. Defaults to 10_000ms. */
	maxDelayMs?: number;
}

/** Configuration for {@link HttpEmitter}. */
export interface HttpEmitterConfig {
	/** Collector endpoint (must be HTTPS in production; HTTP allowed for tests). */
	endpoint: string;
	/** Authentication. Defaults to `{ type: "none" }`. */
	auth?: HttpEmitterAuth;
	/**
	 * Delivery strategy.
	 * - `sync` (default): emit() resolves when the collector acknowledges.
	 *   Provides at-least-once delivery up to the retry budget.
	 * - `fire-and-forget`: emit() schedules the POST and resolves immediately,
	 *   swallowing any error (logged at debug). No delivery guarantee.
	 */
	strategy?: "sync" | "fire-and-forget";
	/** Retry policy for 5xx and network errors. */
	retry?: RetryConfig;
	/** Per-request timeout in milliseconds. Defaults to 5000ms. */
	timeoutMs?: number;
	/**
	 * Hook for fire-and-forget background errors. Defaults to no-op; pass
	 * `console.debug` or a structured logger to surface drops.
	 */
	debugLog?: (message: string, attrs: Record<string, unknown>) => void;
	/**
	 * Test hook: replace the default `globalThis.fetch` with a custom
	 * implementation. Only used by the unit-test suite — production callers
	 * should leave this unset.
	 */
	fetch?: typeof fetch;
}
