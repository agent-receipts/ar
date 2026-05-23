/**
 * BufferingEmitter — wraps a downstream {@link Emitter} and buffers
 * receipts in memory, flushing them on a configurable interval or batch
 * size.
 *
 * The contract with the downstream emitter is per-receipt, NOT batched —
 * a flush calls `inner.emit(receipt)` once per buffered receipt.
 *
 * !!! CRASH-LOSS RISK !!!
 * Buffered receipts are lost if the process exits before {@link flush}
 * completes. This emitter is NOT suitable for environments where audit
 * completeness is critical. Use a synchronous {@link HttpEmitter} (or a
 * persistent WAL — tracked separately) when every receipt must reach the
 * collector.
 */

import type { AgentReceipt } from "../receipt/types.js";
import type { Emitter } from "./types.js";

export interface BufferingEmitterConfig {
	inner: Emitter;
	/** Flush when the buffer reaches this size. Must be >= 1. */
	maxBatchSize: number;
	/** Flush every N milliseconds while receipts are buffered. Must be >= 1. */
	flushIntervalMs: number;
}

export class BufferingEmitter implements Emitter {
	private readonly inner: Emitter;
	private readonly maxBatchSize: number;
	private readonly flushIntervalMs: number;

	private readonly buffer: AgentReceipt[] = [];
	private timer: ReturnType<typeof setTimeout> | null = null;
	private closed = false;
	// Serialise concurrent flush() calls so the downstream sees one ordered
	// sequence even when emit() and an interval tick race.
	private flushChain: Promise<void> = Promise.resolve();

	constructor(config: BufferingEmitterConfig) {
		if (config.maxBatchSize < 1) {
			throw new Error("BufferingEmitter: maxBatchSize must be >= 1");
		}
		if (config.flushIntervalMs < 1) {
			throw new Error("BufferingEmitter: flushIntervalMs must be >= 1");
		}
		this.inner = config.inner;
		this.maxBatchSize = config.maxBatchSize;
		this.flushIntervalMs = config.flushIntervalMs;
	}

	async emit(receipt: AgentReceipt): Promise<void> {
		if (this.closed) {
			throw new Error("BufferingEmitter: closed");
		}
		this.buffer.push(receipt);
		if (this.buffer.length >= this.maxBatchSize) {
			await this.flush();
			return;
		}
		this.scheduleTimer();
	}

	/**
	 * Drain the buffer through the downstream emitter, one receipt at a
	 * time. Resolves once every buffered receipt has been delivered (or the
	 * downstream has thrown for one). If multiple calls overlap they are
	 * serialised — the second await observes the first call's completion.
	 */
	flush(): Promise<void> {
		const next = this.flushChain.then(() => this.doFlush());
		this.flushChain = next.then(
			() => {},
			() => {},
		);
		return next;
	}

	/**
	 * Stop the interval timer and flush the remaining buffer. After close
	 * subsequent {@link emit} calls throw.
	 */
	async close(): Promise<void> {
		if (this.closed) {
			return;
		}
		this.closed = true;
		this.cancelTimer();
		await this.flush();
	}

	private async doFlush(): Promise<void> {
		this.cancelTimer();
		// Splice once — anything emitted while we're flushing goes into the
		// next batch, not this one. This keeps the chain progressing even if
		// the downstream is slow.
		const batch = this.buffer.splice(0, this.buffer.length);
		const errors: unknown[] = [];
		for (const receipt of batch) {
			// Attempt every receipt — failing fast on the first error would
			// silently drop receipts already removed from the buffer.
			try {
				await this.inner.emit(receipt);
			} catch (err) {
				errors.push(err);
			}
		}
		if (errors.length === 1) {
			throw errors[0];
		}
		if (errors.length > 1) {
			throw new AggregateError(
				errors,
				`BufferingEmitter: ${errors.length} of ${batch.length} receipts failed`,
			);
		}
	}

	private scheduleTimer(): void {
		if (this.timer !== null) {
			return;
		}
		this.timer = setTimeout(() => {
			this.timer = null;
			// Swallow errors from the timer-driven flush: they would otherwise
			// become unhandled promise rejections. Real callers should rely on
			// the explicit flush()/close() return values for error surfacing.
			void this.flush().catch(() => {});
		}, this.flushIntervalMs);
		// Don't keep the Node event loop alive solely for the flush timer.
		const t = this.timer as { unref?: () => void };
		if (typeof t.unref === "function") {
			t.unref();
		}
	}

	private cancelTimer(): void {
		if (this.timer !== null) {
			clearTimeout(this.timer);
			this.timer = null;
		}
	}
}
