/**
 * WalEmitter — at-least-once delivery via a write-ahead log (ADR-0020
 * §"At-least-once delivery and the WAL", supersedes ADR-0019 §O3).
 *
 * Wraps an inner {@link Emitter} (typically {@link HttpEmitter} in `sync`
 * mode) and records every receipt in a {@link Wal} *before* attempting
 * delivery. The entry is cleared only once the inner emitter acknowledges
 * (HttpEmitter resolves on collector 201 or 409). If delivery fails the
 * entry survives, so the receipt can be re-delivered on the next
 * {@link WalEmitter.replay} (process restart) or {@link WalEmitter.flush}
 * (graceful shutdown).
 *
 * Two backends ship:
 *
 *  - {@link FileWal} — durable, for long-lived compute (EC2/VM/bare metal).
 *    Entries survive process restart; call {@link WalEmitter.replay} once at
 *    startup, before accepting new emissions, to drain anything left behind
 *    by a previous crash.
 *  - {@link MemoryWal} — in-memory only, for ephemeral compute (Lambda,
 *    Cloud Run, Fargate) where no persistent disk is available. Pending
 *    entries are lost on a hard timeout; on SIGTERM call
 *    {@link WalEmitter.flush} with a short deadline and, if it reports
 *    receipts still pending, emit a terminal `agent_end { status:
 *    "interrupted" }` receipt per ADR-0019 §P1.
 *
 * Recommended ephemeral shutdown wiring (the SDK does not install signal
 * handlers — that is the caller's responsibility, matching the rest of the
 * emitter layer):
 *
 * ```ts
 * process.on("SIGTERM", async () => {
 *   const remaining = await walEmitter.flush(2_000);
 *   if (remaining > 0) {
 *     // best-effort: sign + emit agent_end { status: "interrupted" }
 *   }
 * });
 * ```
 *
 * The WAL is a local delivery aid, not part of the receipt protocol — its
 * on-disk format is private and is not required to match across SDKs.
 */

import {
	mkdir,
	open,
	readdir,
	readFile,
	rename,
	unlink,
} from "node:fs/promises";
import { join } from "node:path";
import type { AgentReceipt } from "../receipt/types.js";
import type { Emitter } from "./types.js";

/**
 * Backend that durably records receipts awaiting acknowledgement.
 *
 * Implementations must preserve append order in {@link Wal.list} and treat a
 * repeated {@link Wal.append} of the same receipt `id` as an idempotent
 * overwrite (it must not create a second entry or change the entry's
 * position in the order).
 */
export interface Wal {
	/** Durably record a receipt as pending. Idempotent on `receipt.id`. */
	append(receipt: AgentReceipt): Promise<void>;
	/** Drop a receipt once acknowledged. No-op when the id is unknown. */
	remove(id: string): Promise<void>;
	/** Pending receipts in append order. */
	list(): Promise<AgentReceipt[]>;
}

/** Outcome of a {@link WalEmitter.replay} or {@link WalEmitter.flush}. */
export interface WalDrainResult {
	/** Receipts acknowledged and cleared from the WAL during the drain. */
	delivered: number;
	/** Receipts still pending afterwards (delivery failed or deadline hit). */
	remaining: number;
}

/** Configuration for {@link WalEmitter}. */
export interface WalEmitterConfig {
	/** The emitter that performs the actual delivery (e.g. an HttpEmitter). */
	inner: Emitter;
	/** The write-ahead log backend ({@link FileWal} or {@link MemoryWal}). */
	wal: Wal;
}

/**
 * In-memory write-ahead log. Entries live only for the lifetime of the
 * process — suitable for ephemeral compute where persistent disk is not
 * available. Receipt loss is possible on a hard crash or timeout (see
 * {@link WalEmitter.flush}).
 */
export class MemoryWal implements Wal {
	// Map iteration order is insertion order, and re-setting an existing key
	// keeps its original position — exactly the idempotent-overwrite semantics
	// the Wal contract requires.
	private readonly entries = new Map<string, AgentReceipt>();

	append(receipt: AgentReceipt): Promise<void> {
		this.entries.set(receipt.id, receipt);
		return Promise.resolve();
	}

	remove(id: string): Promise<void> {
		this.entries.delete(id);
		return Promise.resolve();
	}

	list(): Promise<AgentReceipt[]> {
		return Promise.resolve(Array.from(this.entries.values()));
	}
}

// Zero-padded width for the monotonic entry index encoded in each filename.
// 16 digits comfortably exceeds any realistic pending-entry count and keeps
// lexical sort order equal to numeric order.
const INDEX_WIDTH = 16;
const ENTRY_RE = /^(\d{16})\.json$/;

interface FileEntry {
	index: number;
	receipt: AgentReceipt;
}

/**
 * File-backed write-ahead log. Each pending receipt is one JSON file in
 * `dir`, named by a zero-padded monotonic index so that directory order
 * equals append order. Writes are atomic (temp file + fsync + rename), so a
 * crash mid-write never leaves a half-written entry that replay would choke
 * on. Survives process restart: the directory is scanned lazily on first use
 * and any leftover entries become the replay backlog.
 */
export class FileWal implements Wal {
	private readonly dir: string;
	// id -> entry. Loaded lazily on first use so construction stays synchronous,
	// matching `new FileWal(dir)` ergonomics elsewhere in the emitter layer.
	private readonly byId = new Map<string, FileEntry>();
	private maxIndex = 0;
	private loaded = false;
	// Serialises every operation through one promise chain so interleaved
	// awaits can't race the index counter or the on-disk files (the Node event
	// loop is single-threaded but `async` methods still interleave at each
	// await). This is the TS counterpart to the Python backend's threading.Lock
	// and the Go backend's sync.Mutex.
	private opChain: Promise<unknown> = Promise.resolve();

	constructor(dir: string) {
		this.dir = dir;
	}

	append(receipt: AgentReceipt): Promise<void> {
		return this.runExclusive(async () => {
			await this.ensureLoaded();
			// Reuse the existing slot on idempotent re-append so the entry keeps
			// its position in the order; otherwise take the next index.
			const existing = this.byId.get(receipt.id);
			const index = existing ? existing.index : ++this.maxIndex;
			await this.writeEntry(index, receipt);
			this.byId.set(receipt.id, { index, receipt });
		});
	}

	remove(id: string): Promise<void> {
		return this.runExclusive(async () => {
			await this.ensureLoaded();
			const entry = this.byId.get(id);
			if (!entry) {
				return;
			}
			this.byId.delete(id);
			try {
				await unlink(this.path(entry.index));
			} catch (err) {
				// A missing file is fine — the entry is gone either way.
				if (!isNotFound(err)) {
					throw err;
				}
			}
		});
	}

	list(): Promise<AgentReceipt[]> {
		return this.runExclusive(async () => {
			await this.ensureLoaded();
			return Array.from(this.byId.values())
				.sort((a, b) => a.index - b.index)
				.map((e) => e.receipt);
		});
	}

	// Queue `fn` after any in-flight operation. The chain advances regardless of
	// whether the prior op resolved or rejected, so one failure can't wedge the
	// backend; the caller still sees this op's own outcome.
	private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
		const result = this.opChain.then(fn, fn);
		this.opChain = result.then(
			() => {},
			() => {},
		);
		return result;
	}

	// Caller must hold the op chain (run inside runExclusive). Scans the
	// directory exactly once; on failure `loaded` stays false so a later call
	// retries rather than caching the error forever.
	private async ensureLoaded(): Promise<void> {
		if (this.loaded) {
			return;
		}
		await this.load();
		this.loaded = true;
	}

	private async load(): Promise<void> {
		await mkdir(this.dir, { recursive: true });
		const names = await readdir(this.dir);
		// Sort by index so a duplicate id (possible if a crash interleaved an
		// idempotent rewrite) resolves to the highest-index file; the stale
		// lower-index file is unlinked.
		const matched = names
			.map((name) => ({ name, m: ENTRY_RE.exec(name) }))
			.filter((x): x is { name: string; m: RegExpExecArray } => x.m !== null)
			.map((x) => ({ name: x.name, index: Number(x.m[1]) }))
			.sort((a, b) => a.index - b.index);

		for (const { name, index } of matched) {
			if (index > this.maxIndex) {
				this.maxIndex = index;
			}
			let receipt: AgentReceipt;
			try {
				const raw = await readFile(join(this.dir, name), "utf8");
				receipt = JSON.parse(raw) as AgentReceipt;
			} catch {
				// A torn or unreadable entry (e.g. a leftover temp that matched
				// loosely, or truncated JSON from a hard crash) is dropped rather
				// than failing the whole load — the receipt was never acked, so
				// at worst the chain shows a gap, which the verifier surfaces.
				continue;
			}
			const prior = this.byId.get(receipt.id);
			if (prior) {
				await this.unlinkQuiet(prior.index);
			}
			this.byId.set(receipt.id, { index, receipt });
		}
	}

	private async writeEntry(
		index: number,
		receipt: AgentReceipt,
	): Promise<void> {
		const finalPath = this.path(index);
		const tmpPath = `${finalPath}.tmp`;
		const fh = await open(tmpPath, "w");
		try {
			await fh.writeFile(JSON.stringify(receipt));
			// fsync the data before the rename so a crash can't expose a
			// rename-completed-but-data-lost entry.
			await fh.sync();
		} finally {
			await fh.close();
		}
		await rename(tmpPath, finalPath);
	}

	private async unlinkQuiet(index: number): Promise<void> {
		try {
			await unlink(this.path(index));
		} catch (err) {
			if (!isNotFound(err)) {
				throw err;
			}
		}
	}

	private path(index: number): string {
		return join(this.dir, `${String(index).padStart(INDEX_WIDTH, "0")}.json`);
	}
}

function isNotFound(err: unknown): boolean {
	return (
		typeof err === "object" &&
		err !== null &&
		(err as { code?: string }).code === "ENOENT"
	);
}

/**
 * Emitter providing at-least-once delivery on top of an inner emitter via a
 * write-ahead log. See the module doc for the durable vs in-memory backend
 * choice and the recommended SIGTERM wiring.
 */
export class WalEmitter implements Emitter {
	private readonly inner: Emitter;
	private readonly wal: Wal;

	constructor(config: WalEmitterConfig) {
		this.inner = config.inner;
		this.wal = config.wal;
	}

	/**
	 * Write the receipt to the WAL, deliver it through the inner emitter, then
	 * clear the WAL entry on acknowledgement. If delivery throws, the entry is
	 * left in the WAL for later {@link replay}/{@link flush} and the error is
	 * re-thrown to the caller.
	 */
	async emit(receipt: AgentReceipt): Promise<void> {
		await this.wal.append(receipt);
		await this.inner.emit(receipt);
		await this.wal.remove(receipt.id);
	}

	/**
	 * Re-deliver every receipt left unacknowledged in the WAL. Call once at
	 * startup, before accepting new emissions, to drain a backlog left by a
	 * previous crash (durable backend) or to retry within a warm invocation.
	 * Each entry that the inner emitter acknowledges is cleared; failures stay
	 * in the WAL and do not block the remaining entries.
	 */
	replay(): Promise<WalDrainResult> {
		return this.drain(undefined);
	}

	/**
	 * Best-effort delivery of all pending receipts, bounded by a wall-clock
	 * deadline. Intended for graceful shutdown on SIGTERM in ephemeral compute.
	 * Returns the number of receipts still pending when the deadline elapses
	 * (0 means the WAL drained cleanly). A non-zero result is the caller's cue
	 * to emit `agent_end { status: "interrupted" }` per ADR-0019 §P1.
	 *
	 * @param deadlineMs Wall-clock budget in milliseconds. Defaults to 2000.
	 */
	flush(deadlineMs = 2_000): Promise<number> {
		return this.drain(deadlineMs).then((r) => r.remaining);
	}

	/** Count of receipts currently awaiting acknowledgement. */
	async pending(): Promise<number> {
		return (await this.wal.list()).length;
	}

	private async drain(deadlineMs: number | undefined): Promise<WalDrainResult> {
		const pending = await this.wal.list();
		const deadline =
			deadlineMs === undefined ? undefined : Date.now() + deadlineMs;
		let delivered = 0;

		for (const receipt of pending) {
			if (deadline !== undefined && Date.now() >= deadline) {
				break;
			}
			try {
				if (deadline === undefined) {
					await this.inner.emit(receipt);
				} else {
					// The inner emitter can't be interrupted mid-call (HttpEmitter
					// owns its own per-request timeout/retry budget), so race the
					// delivery against the remaining deadline. If the delivery
					// settles after the race is lost it does NOT clear its WAL
					// entry (nothing awaits it past this point), so the entry
					// stays pending and is re-delivered on the next drain —
					// harmless because a duplicate POST is idempotent at the
					// collector (409).
					const remaining = deadline - Date.now();
					await raceDeadline(this.inner.emit(receipt), remaining);
				}
				await this.wal.remove(receipt.id);
				delivered++;
			} catch {
				// Leave the entry for the next drain. Continue so one stuck
				// receipt doesn't strand the rest.
			}
		}

		const remaining = (await this.wal.list()).length;
		return { delivered, remaining };
	}
}

/** Reject if `ms` elapses before `promise` settles. */
function raceDeadline<T>(promise: Promise<T>, ms: number): Promise<T> {
	if (ms <= 0) {
		return Promise.reject(new Error("deadline elapsed"));
	}
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("deadline elapsed")), ms);
		(timer as { unref?: () => void }).unref?.();
		promise.then(
			(v) => {
				clearTimeout(timer);
				resolve(v);
			},
			(e) => {
				clearTimeout(timer);
				reject(e);
			},
		);
	});
}
