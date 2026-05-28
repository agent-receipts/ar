/**
 * Data-driven conformance runner for the shared emit failure contract vector
 * (cross-sdk-tests/emit_failure_vectors.json, ADR-0025). Loads the vector,
 * iterates every case, runs it against DaemonEmitter (default mode, no
 * listener), maps the outcome to an outcome category, and asserts it matches
 * `expect`. The vector is the single source of truth for which cases exist:
 * this runner throws on any case name it does not handle, so adding a case to
 * the JSON breaks this SDK until it is implemented here.
 */

import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	DaemonEmitter,
	type EmitEvent,
	EmitTransportError,
} from "./daemon-emitter.js";

const currentDir = dirname(fileURLToPath(import.meta.url));
const vectorPath = resolve(
	currentDir,
	"../../../cross-sdk-tests/emit_failure_vectors.json",
);

interface FailureVector {
	cases: Array<{ name: string; expect: string }>;
}

const vector: FailureVector = JSON.parse(readFileSync(vectorPath, "utf8"));

/**
 * Map an emit outcome to an outcome category. Transport failures are
 * EmitTransportError instances (ADR-0025); caller bugs are plain Error
 * instances — distinct types, so the contract's distinguishability requirement
 * holds without string matching.
 */
function classify(err: Error | null): string {
	if (err === null) {
		return "success";
	}
	if (err instanceof EmitTransportError) {
		return "transport_error";
	}
	return "caller_error";
}

describe("emit failure contract vector (ADR-0025)", () => {
	expect(vector.cases.length).toBeGreaterThan(0);

	for (const c of vector.cases) {
		it(c.name, async () => {
			const base = process.platform === "darwin" ? "/tmp" : tmpdir();
			const sockPath = join(base, `ar-vec-${process.pid}-${c.name}.sock`);
			// Default mode (no bestEffort) against a socket with no listener.
			const emitter = new DaemonEmitter({ socketPath: sockPath });

			const event: EmitEvent = {
				channel: "sdk",
				tool: { name: "noop" },
				decision: "allowed",
			};
			let err: Error | null;
			if (c.name === "dial_failure_unreachable_socket") {
				err = await emitter.emit(event);
			} else if (c.name === "caller_bug_invalid_decision") {
				err = await emitter.emit({
					...event,
					// @ts-expect-error intentionally invalid decision to exercise caller-bug validation
					decision: "bogus",
				});
			} else {
				emitter.close();
				throw new Error(
					`unhandled emit-failure case ${c.name}: implement it or remove it from the vector`,
				);
			}
			emitter.close();

			expect(classify(err)).toBe(c.expect);
		});
	}
});
