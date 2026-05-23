/**
 * CompositeEmitter — forwards each receipt to a list of child emitters
 * sequentially.
 *
 * Semantics: every child is attempted, in order. If a child throws, the
 * error is captured and the remaining children are still attempted. When
 * at least one child threw, `emit()` rejects with an {@link AggregateError}
 * whose `errors` array holds the captured underlying errors in the order
 * they were thrown.
 *
 * Use cases: writing to a primary collector plus an offsite archive, or
 * dual-writing during an endpoint migration.
 *
 * Per ADR-0020 §"CompositeEmitter" every child must implement the new
 * {@link Emitter} interface; {@link DaemonEmitter} does not (yet) — it
 * takes unsigned event frames, not signed receipts.
 */

import type { AgentReceipt } from "../receipt/types.js";
import type { Emitter } from "./types.js";

export class CompositeEmitter implements Emitter {
	private readonly children: readonly Emitter[];

	constructor(children: readonly Emitter[]) {
		this.children = children;
	}

	async emit(receipt: AgentReceipt): Promise<void> {
		const errors: unknown[] = [];
		for (const child of this.children) {
			try {
				await child.emit(receipt);
			} catch (err) {
				errors.push(err);
			}
		}
		if (errors.length > 0) {
			throw new AggregateError(
				errors,
				`CompositeEmitter: ${errors.length} of ${this.children.length} child emitters failed`,
			);
		}
	}
}
