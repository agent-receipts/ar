/**
 * Tests for {@link CompositeEmitter}: sequential fan-out with error
 * aggregation.
 */

import { describe, expect, it } from "vitest";
import type { AgentReceipt } from "../receipt/types.js";
import { CompositeEmitter } from "./composite.js";
import { InMemoryEmitter } from "./in-memory.js";
import type { Emitter } from "./types.js";

function fakeReceipt(id: string): AgentReceipt {
	return { id } as unknown as AgentReceipt;
}

/** Emitter that always throws — used to assert error aggregation. */
class FailingEmitter implements Emitter {
	readonly calls: AgentReceipt[] = [];
	constructor(private readonly err: Error) {}
	emit(receipt: AgentReceipt): Promise<void> {
		this.calls.push(receipt);
		return Promise.reject(this.err);
	}
}

describe("CompositeEmitter", () => {
	it("forwards each receipt to every child in order", async () => {
		const a = new InMemoryEmitter();
		const b = new InMemoryEmitter();
		const c = new InMemoryEmitter();
		const composite = new CompositeEmitter([a, b, c]);

		await composite.emit(fakeReceipt("r1"));
		await composite.emit(fakeReceipt("r2"));

		for (const child of [a, b, c]) {
			expect(child.received.map((r) => r.id)).toEqual(["r1", "r2"]);
		}
	});

	it("continues past a failing child and still calls the rest", async () => {
		const before = new InMemoryEmitter();
		const failing = new FailingEmitter(new Error("kaboom"));
		const after = new InMemoryEmitter();
		const composite = new CompositeEmitter([before, failing, after]);

		await expect(composite.emit(fakeReceipt("r"))).rejects.toBeInstanceOf(
			AggregateError,
		);

		expect(before.received.map((r) => r.id)).toEqual(["r"]);
		expect(failing.calls.map((r) => r.id)).toEqual(["r"]);
		expect(after.received.map((r) => r.id)).toEqual(["r"]);
	});

	it("aggregates errors in the order they were thrown", async () => {
		const err1 = new Error("first");
		const err2 = new Error("second");
		const composite = new CompositeEmitter([
			new FailingEmitter(err1),
			new InMemoryEmitter(),
			new FailingEmitter(err2),
		]);

		try {
			await composite.emit(fakeReceipt("r"));
			throw new Error("composite.emit did not throw");
		} catch (err) {
			expect(err).toBeInstanceOf(AggregateError);
			const agg = err as AggregateError;
			expect(agg.errors).toEqual([err1, err2]);
		}
	});

	it("resolves cleanly when there are no children", async () => {
		const composite = new CompositeEmitter([]);
		await expect(composite.emit(fakeReceipt("r"))).resolves.toBeUndefined();
	});

	it("resolves cleanly when every child succeeds", async () => {
		const a = new InMemoryEmitter();
		const b = new InMemoryEmitter();
		const composite = new CompositeEmitter([a, b]);
		await expect(composite.emit(fakeReceipt("r"))).resolves.toBeUndefined();
	});
});
