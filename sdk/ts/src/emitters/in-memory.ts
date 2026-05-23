/**
 * InMemoryEmitter — test double that captures emitted receipts in an
 * exposed array.
 *
 * Performs no I/O and provides no delivery guarantee. Use this in unit and
 * integration tests where the assertion is against the receipts that
 * passed through the emitter, not against a remote collector.
 *
 * NOT for production use.
 */

import type { AgentReceipt } from "../receipt/types.js";
import type { Emitter } from "./types.js";

export class InMemoryEmitter implements Emitter {
	private readonly _received: AgentReceipt[] = [];

	/** All receipts passed to {@link emit}, in arrival order. */
	get received(): readonly AgentReceipt[] {
		return this._received;
	}

	emit(receipt: AgentReceipt): Promise<void> {
		this._received.push(receipt);
		return Promise.resolve();
	}

	/** Clear the recorded receipts. Useful between test cases. */
	clear(): void {
		this._received.length = 0;
	}
}
