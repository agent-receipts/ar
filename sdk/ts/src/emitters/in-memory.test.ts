/**
 * Tests for {@link InMemoryEmitter}: the array-backed test double.
 */

import { describe, expect, it } from "vitest";
import type { AgentReceipt } from "../receipt/types.js";
import { InMemoryEmitter } from "./in-memory.js";

function fakeReceipt(id: string): AgentReceipt {
	// Minimal cast — these tests only care about pass-through identity, not
	// the receipt internals.
	return { id } as unknown as AgentReceipt;
}

describe("InMemoryEmitter", () => {
	it("starts with an empty received list", () => {
		const e = new InMemoryEmitter();
		expect(e.received).toEqual([]);
	});

	it("appends each emitted receipt in arrival order", async () => {
		const e = new InMemoryEmitter();
		await e.emit(fakeReceipt("a"));
		await e.emit(fakeReceipt("b"));
		await e.emit(fakeReceipt("c"));
		expect(e.received.map((r) => r.id)).toEqual(["a", "b", "c"]);
	});

	it("clear() empties the recorded receipts", async () => {
		const e = new InMemoryEmitter();
		await e.emit(fakeReceipt("a"));
		e.clear();
		expect(e.received).toEqual([]);
	});

	it("performs no I/O — emit() resolves synchronously", async () => {
		// If this test takes more than a few ms there's I/O happening somewhere
		// it shouldn't be.
		const e = new InMemoryEmitter();
		const start = Date.now();
		for (let i = 0; i < 1_000; i++) {
			await e.emit(fakeReceipt(`r-${i}`));
		}
		expect(Date.now() - start).toBeLessThan(100);
		expect(e.received).toHaveLength(1_000);
	});
});
