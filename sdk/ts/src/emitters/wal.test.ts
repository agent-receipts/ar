/**
 * Tests for the write-ahead log emitter (ADR-0020 at-least-once delivery).
 *
 * Covers both WAL backends (MemoryWal, FileWal) and the WalEmitter contract:
 * write-ahead before delivery, clear on ack, retain on failure, replay after
 * a simulated crash, and deadline-bounded flush for ephemeral shutdown.
 */

import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AgentReceipt } from "../receipt/types.js";
import { makeReceipt } from "../test-utils/receipts.js";
import type { Emitter } from "./types.js";
import { EmitError } from "./types.js";
import { FileWal, MemoryWal, type Wal, WalEmitter } from "./wal.js";

function receipt(id: string, sequence = 1): AgentReceipt {
	return makeReceipt({ id, sequence });
}

/**
 * Inner emitter whose behaviour is scriptable per receipt id. Default is to
 * succeed; ids in `failing` throw until removed via {@link FlakyEmitter.heal}.
 */
class FlakyEmitter implements Emitter {
	readonly delivered: string[] = [];
	private readonly failing = new Set<string>();
	private delayMs = 0;

	failOn(...ids: string[]): void {
		for (const id of ids) this.failing.add(id);
	}

	heal(...ids: string[]): void {
		for (const id of ids) this.failing.delete(id);
	}

	setDelay(ms: number): void {
		this.delayMs = ms;
	}

	async emit(r: AgentReceipt): Promise<void> {
		if (this.delayMs > 0) {
			await new Promise((res) => setTimeout(res, this.delayMs));
		}
		if (this.failing.has(r.id)) {
			throw new EmitError(`flaky: refusing ${r.id}`, { status: 503 });
		}
		this.delivered.push(r.id);
	}
}

describe("MemoryWal", () => {
	it("appends, lists in order, and removes", async () => {
		const wal = new MemoryWal();
		await wal.append(receipt("a"));
		await wal.append(receipt("b"));
		await wal.append(receipt("c"));
		expect((await wal.list()).map((r) => r.id)).toEqual(["a", "b", "c"]);

		await wal.remove("b");
		expect((await wal.list()).map((r) => r.id)).toEqual(["a", "c"]);
	});

	it("treats re-append of the same id as an idempotent overwrite", async () => {
		const wal = new MemoryWal();
		await wal.append(receipt("a", 1));
		await wal.append(receipt("b", 2));
		await wal.append(receipt("a", 99)); // re-append keeps position
		const list = await wal.list();
		expect(list.map((r) => r.id)).toEqual(["a", "b"]);
		expect(list[0]?.credentialSubject.chain.sequence).toBe(99);
	});

	it("remove of an unknown id is a no-op", async () => {
		const wal = new MemoryWal();
		await wal.append(receipt("a"));
		await wal.remove("missing");
		expect((await wal.list()).map((r) => r.id)).toEqual(["a"]);
	});
});

describe("FileWal", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "ar-wal-"));
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("persists entries and lists them in append order", async () => {
		const wal = new FileWal(dir);
		await wal.append(receipt("a"));
		await wal.append(receipt("b"));
		expect((await wal.list()).map((r) => r.id)).toEqual(["a", "b"]);
		// One JSON file per entry, no leftover temp files.
		const files = readdirSync(dir);
		expect(files).toHaveLength(2);
		expect(files.every((f) => f.endsWith(".json"))).toBe(true);
	});

	it.skipIf(process.platform === "win32")(
		"writes entry files and the WAL dir owner-only (0600/0700)",
		async () => {
			// Fresh subdir the FileWal must create itself, so we assert its
			// mkdir mode rather than the mkdtemp parent's.
			const sub = join(dir, "wal-sub");
			const wal = new FileWal(sub);
			await wal.append(receipt("a"));
			const entry = readdirSync(sub).find((f) => f.endsWith(".json"));
			if (entry === undefined) throw new Error("no entry file written");
			expect(statSync(join(sub, entry)).mode & 0o777).toBe(0o600);
			expect(statSync(sub).mode & 0o777).toBe(0o700);
		},
	);

	it("removes entries and deletes their files", async () => {
		const wal = new FileWal(dir);
		await wal.append(receipt("a"));
		await wal.append(receipt("b"));
		await wal.remove("a");
		expect((await wal.list()).map((r) => r.id)).toEqual(["b"]);
		expect(readdirSync(dir)).toHaveLength(1);
	});

	it("survives a restart by reloading entries from disk", async () => {
		const first = new FileWal(dir);
		await first.append(receipt("a", 1));
		await first.append(receipt("b", 2));
		await first.remove("a");

		// Simulate a fresh process: a new FileWal over the same directory.
		const second = new FileWal(dir);
		const list = await second.list();
		expect(list.map((r) => r.id)).toEqual(["b"]);
		expect(list[0]?.credentialSubject.chain.sequence).toBe(2);
	});

	it("preserves order across a restart for a new appended entry", async () => {
		const first = new FileWal(dir);
		await first.append(receipt("a"));
		await first.append(receipt("b"));

		const second = new FileWal(dir);
		await second.append(receipt("c"));
		expect((await second.list()).map((r) => r.id)).toEqual(["a", "b", "c"]);
	});

	it("idempotent re-append rewrites in place without reordering", async () => {
		const wal = new FileWal(dir);
		await wal.append(receipt("a", 1));
		await wal.append(receipt("b", 2));
		await wal.append(receipt("a", 50));
		const list = await wal.list();
		expect(list.map((r) => r.id)).toEqual(["a", "b"]);
		expect(list[0]?.credentialSubject.chain.sequence).toBe(50);
		expect(readdirSync(dir).filter((f) => f.endsWith(".json"))).toHaveLength(2);
	});

	it("serialises concurrent appends without duplicating or losing entries", async () => {
		const wal = new FileWal(dir);
		// Fire many appends without awaiting between them — they must queue
		// through the op chain rather than racing the index counter or files.
		await Promise.all([
			wal.append(receipt("a", 1)),
			wal.append(receipt("b", 2)),
			wal.append(receipt("c", 3)),
			// Same id concurrently with itself: must collapse to one entry/file.
			wal.append(receipt("a", 1)),
		]);
		const ids = (await wal.list()).map((r) => r.id).sort();
		expect(ids).toEqual(["a", "b", "c"]);
		// One file per distinct id — no orphan from the same-id race.
		expect(readdirSync(dir).filter((f) => f.endsWith(".json"))).toHaveLength(3);
	});

	it("drops a torn entry rather than failing the load", async () => {
		const wal = new FileWal(dir);
		await wal.append(receipt("a"));
		await wal.append(receipt("b"));
		// Corrupt one entry as a hard-crash mid-write would.
		const files = readdirSync(dir)
			.filter((f) => f.endsWith(".json"))
			.sort();
		const corrupt = files[0];
		if (corrupt === undefined) throw new Error("no entry to corrupt");
		const { writeFileSync } = await import("node:fs");
		writeFileSync(join(dir, corrupt), "{ not valid json");

		const reloaded = new FileWal(dir);
		// The readable entry survives; the torn one is dropped.
		expect((await reloaded.list()).map((r) => r.id)).toEqual(["b"]);
	});
});

describe("WalEmitter", () => {
	let dir: string;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "ar-walemit-"));
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("clears the WAL entry once delivery is acknowledged", async () => {
		const wal: Wal = new MemoryWal();
		const inner = new FlakyEmitter();
		const emitter = new WalEmitter({ inner, wal });

		await emitter.emit(receipt("a"));

		expect(inner.delivered).toEqual(["a"]);
		expect(await emitter.pending()).toBe(0);
	});

	it("retains the WAL entry and rethrows when delivery fails", async () => {
		const wal: Wal = new MemoryWal();
		const inner = new FlakyEmitter();
		inner.failOn("a");
		const emitter = new WalEmitter({ inner, wal });

		await expect(emitter.emit(receipt("a"))).rejects.toBeInstanceOf(EmitError);
		expect(inner.delivered).toEqual([]);
		expect(await emitter.pending()).toBe(1);
	});

	it("replay re-delivers everything left unacknowledged", async () => {
		const wal: Wal = new MemoryWal();
		const inner = new FlakyEmitter();
		inner.failOn("a", "b");
		const emitter = new WalEmitter({ inner, wal });

		await expect(emitter.emit(receipt("a"))).rejects.toThrow();
		await expect(emitter.emit(receipt("b"))).rejects.toThrow();
		expect(await emitter.pending()).toBe(2);

		// Collector recovers; replay drains the backlog.
		inner.heal("a", "b");
		const result = await emitter.replay();
		expect(result).toEqual({ delivered: 2, remaining: 0 });
		expect(inner.delivered).toEqual(["a", "b"]);
		expect(await emitter.pending()).toBe(0);
	});

	it("replay leaves still-failing entries and does not block the rest", async () => {
		const wal: Wal = new MemoryWal();
		const inner = new FlakyEmitter();
		inner.failOn("a", "b", "c");
		const emitter = new WalEmitter({ inner, wal });
		await expect(emitter.emit(receipt("a"))).rejects.toThrow();
		await expect(emitter.emit(receipt("b"))).rejects.toThrow();
		await expect(emitter.emit(receipt("c"))).rejects.toThrow();

		// Only the middle entry stays broken.
		inner.heal("a", "c");
		const result = await emitter.replay();
		expect(result).toEqual({ delivered: 2, remaining: 1 });
		expect(inner.delivered.sort()).toEqual(["a", "c"]);
		expect((await wal.list()).map((r) => r.id)).toEqual(["b"]);
	});

	it("replays a durable backlog after a simulated process restart", async () => {
		// Process 1: delivery fails, entry persists to disk, then the process
		// "crashes" (we drop the emitter).
		{
			const wal = new FileWal(dir);
			const inner = new FlakyEmitter();
			inner.failOn("a");
			const emitter = new WalEmitter({ inner, wal });
			await expect(emitter.emit(receipt("a"))).rejects.toThrow();
		}

		// Process 2: fresh emitter over the same WAL dir; collector is healthy.
		const wal2 = new FileWal(dir);
		const inner2 = new FlakyEmitter();
		const emitter2 = new WalEmitter({ inner: inner2, wal: wal2 });
		expect(await emitter2.pending()).toBe(1);

		const result = await emitter2.replay();
		expect(result).toEqual({ delivered: 1, remaining: 0 });
		expect(inner2.delivered).toEqual(["a"]);
		expect(readdirSync(dir).filter((f) => f.endsWith(".json"))).toHaveLength(0);
	});

	it("flush returns the count still pending after a clean drain", async () => {
		const wal: Wal = new MemoryWal();
		const inner = new FlakyEmitter();
		inner.failOn("a");
		const emitter = new WalEmitter({ inner, wal });
		await expect(emitter.emit(receipt("a"))).rejects.toThrow();

		inner.heal("a");
		const remaining = await emitter.flush(1_000);
		expect(remaining).toBe(0);
		expect(inner.delivered).toEqual(["a"]);
	});

	it("flush respects the deadline and reports receipts still pending", async () => {
		const wal: Wal = new MemoryWal();
		const inner = new FlakyEmitter();
		// Deliveries are healthy but slow; the deadline cuts the drain short.
		inner.setDelay(200);
		const emitter = new WalEmitter({ inner, wal });
		await wal.append(receipt("a"));
		await wal.append(receipt("b"));

		const remaining = await emitter.flush(50);
		expect(remaining).toBeGreaterThan(0);
	});
});
