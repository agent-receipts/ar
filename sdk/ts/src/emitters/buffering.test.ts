/**
 * Tests for {@link BufferingEmitter}: in-memory batch buffer with timer
 * flush. Tests must use fake timers so the interval behaviour is
 * deterministic.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentReceipt } from "../receipt/types.js";
import { BufferingEmitter } from "./buffering.js";
import { InMemoryEmitter } from "./in-memory.js";
import type { Emitter } from "./types.js";

function fakeReceipt(id: string): AgentReceipt {
	return { id } as unknown as AgentReceipt;
}

class FailingEmitter implements Emitter {
	emit(_receipt: AgentReceipt): Promise<void> {
		return Promise.reject(new Error("downstream failed"));
	}
}

describe("BufferingEmitter", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("rejects invalid maxBatchSize", () => {
		expect(
			() =>
				new BufferingEmitter({
					inner: new InMemoryEmitter(),
					maxBatchSize: 0,
					flushIntervalMs: 50,
				}),
		).toThrow(/maxBatchSize/);
	});

	it("rejects invalid flushIntervalMs", () => {
		expect(
			() =>
				new BufferingEmitter({
					inner: new InMemoryEmitter(),
					maxBatchSize: 2,
					flushIntervalMs: 0,
				}),
		).toThrow(/flushIntervalMs/);
	});

	it("does not flush until the batch fills", async () => {
		const inner = new InMemoryEmitter();
		const buf = new BufferingEmitter({
			inner,
			maxBatchSize: 3,
			flushIntervalMs: 10_000,
		});

		await buf.emit(fakeReceipt("a"));
		await buf.emit(fakeReceipt("b"));
		expect(inner.received).toHaveLength(0);

		await buf.emit(fakeReceipt("c"));
		// Reaching the batch size flushes synchronously.
		expect(inner.received.map((r) => r.id)).toEqual(["a", "b", "c"]);
	});

	it("flushes when the interval elapses even below batch size", async () => {
		const inner = new InMemoryEmitter();
		const buf = new BufferingEmitter({
			inner,
			maxBatchSize: 100,
			flushIntervalMs: 50,
		});

		await buf.emit(fakeReceipt("a"));
		expect(inner.received).toHaveLength(0);

		await vi.advanceTimersByTimeAsync(50);
		// One microtask further to let the flush chain resolve.
		await vi.advanceTimersByTimeAsync(1);
		expect(inner.received.map((r) => r.id)).toEqual(["a"]);
	});

	it("explicit flush() drains the buffer immediately", async () => {
		const inner = new InMemoryEmitter();
		const buf = new BufferingEmitter({
			inner,
			maxBatchSize: 100,
			flushIntervalMs: 10_000,
		});

		await buf.emit(fakeReceipt("a"));
		await buf.emit(fakeReceipt("b"));
		expect(inner.received).toHaveLength(0);
		await buf.flush();
		expect(inner.received.map((r) => r.id)).toEqual(["a", "b"]);
	});

	it("calls inner.emit once per buffered receipt (per-receipt contract)", async () => {
		const inner = new InMemoryEmitter();
		const buf = new BufferingEmitter({
			inner,
			maxBatchSize: 4,
			flushIntervalMs: 10_000,
		});

		await buf.emit(fakeReceipt("a"));
		await buf.emit(fakeReceipt("b"));
		await buf.emit(fakeReceipt("c"));
		await buf.emit(fakeReceipt("d"));

		// Each receipt was delivered individually — the buffer batches the
		// SCHEDULING of delivery, not the wire payload.
		expect(inner.received).toHaveLength(4);
	});

	it("propagates downstream errors out of flush()", async () => {
		const buf = new BufferingEmitter({
			inner: new FailingEmitter(),
			maxBatchSize: 100,
			flushIntervalMs: 10_000,
		});
		await buf.emit(fakeReceipt("a"));
		await expect(buf.flush()).rejects.toThrow(/downstream failed/);
	});

	it("close() drains the buffer and rejects further emits", async () => {
		const inner = new InMemoryEmitter();
		const buf = new BufferingEmitter({
			inner,
			maxBatchSize: 100,
			flushIntervalMs: 10_000,
		});

		await buf.emit(fakeReceipt("a"));
		await buf.close();
		expect(inner.received.map((r) => r.id)).toEqual(["a"]);

		await expect(buf.emit(fakeReceipt("b"))).rejects.toThrow(/closed/);
	});
});
