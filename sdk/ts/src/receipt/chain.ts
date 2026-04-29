import { canonicalize, hashReceipt, sha256 } from "./hash.js";
import { verifyReceipt } from "./signing.js";
import type { AgentReceipt } from "./types.js";

/**
 * Result of verifying a single receipt in a chain.
 */
export interface ReceiptVerification {
	/** Index of the receipt in the chain. */
	index: number;
	/** Receipt id. */
	receiptId: string;
	/** Whether the Ed25519 signature is valid. */
	signatureValid: boolean;
	/** Whether the previous_receipt_hash matches the prior receipt's hash. */
	hashLinkValid: boolean;
	/** Whether the sequence number is correct. */
	sequenceValid: boolean;
}

/**
 * Result of verifying an entire chain.
 */
export interface ChainVerification {
	/** Whether the entire chain is valid. */
	valid: boolean;
	/** Number of receipts verified. */
	length: number;
	/** Per-receipt verification results. */
	receipts: ReceiptVerification[];
	/** Index of the first broken receipt, or -1 if chain is valid. */
	brokenAt: number;
	/** Non-empty when one or more receipts carry response_hash but no response body was supplied. */
	responseHashNote?: string;
	/** Non-empty when verification failed with a descriptive message. */
	error?: string;
}

/**
 * Optional parameters for verifyChain.
 * Omitting any parameter preserves v0.1 behaviour.
 */
export interface ChainVerifyOptions {
	/**
	 * When set, verification fails if the observed chain length does not equal
	 * this value. Provides out-of-band truncation detection.
	 */
	expectedLength?: number;
	/**
	 * When set, verification fails if the SHA-256 hash of the last observed
	 * receipt does not equal this value. Provides out-of-band truncation
	 * detection when the caller knows the expected final receipt hash.
	 */
	expectedFinalHash?: string;
	/**
	 * When true, verification fails if the last observed receipt does not have
	 * chain.terminal: true. Use for chains that must close cleanly.
	 */
	requireTerminal?: boolean;
	/**
	 * Maps receipt id → pre-redacted response body. When a receipt carries
	 * outcome.response_hash and its id appears here, verifyChain recomputes the
	 * hash and fails on mismatch. When the entry is absent an informational note
	 * is emitted instead. An absent body is not a verification failure.
	 */
	responseBodies?: Record<string, unknown>;
}

/**
 * Verify a chain of signed receipts.
 *
 * Checks for each receipt:
 * 1. Ed25519 signature validity
 * 2. Hash linkage: previous_receipt_hash matches SHA-256 of prior receipt
 * 3. Sequence numbers are strictly incrementing
 * 4. Receipt-after-terminal: if any receipt has chain.terminal: true, no
 *    subsequent receipt may reference it (unconditional, spec §7.3.2)
 *
 * Chain verification does NOT detect tail truncation by default — dropping the
 * last N receipts from a chain still produces valid: true. To detect truncation:
 * - Supply expectedLength and/or expectedFinalHash (out-of-band witness)
 * - Supply requireTerminal for chains that must close with chain.terminal: true
 *
 * Chains that are open-ended and have no external witness cannot be detected as
 * truncated. See spec §7.3.1 for the full treatment.
 */
export function verifyChain(
	receipts: AgentReceipt[],
	publicKey: string,
	options?: ChainVerifyOptions,
): ChainVerification {
	if (receipts.length === 0) {
		if (options?.expectedLength !== undefined && options.expectedLength !== 0) {
			return {
				valid: false,
				length: 0,
				receipts: [],
				brokenAt: 0,
				responseHashNote: undefined,
			};
		}
		return { valid: true, length: 0, receipts: [], brokenAt: -1 };
	}

	const results: ReceiptVerification[] = [];
	let brokenAt = -1;
	let previous: AgentReceipt | undefined;

	for (let i = 0; i < receipts.length; i++) {
		const receipt = receipts[i];
		if (!receipt) continue;
		const chain = receipt.credentialSubject.chain;

		const signatureValid = verifyReceipt(receipt, publicKey);

		let hashLinkValid: boolean;
		if (previous === undefined) {
			hashLinkValid = chain.previous_receipt_hash === null;
		} else {
			let previousHash: string;
			try {
				previousHash = hashReceipt(previous);
			} catch (e) {
				const reason = e instanceof Error ? e.message : String(e);
				const prevSeq = previous.credentialSubject.chain.sequence;
				const curSeq = chain.sequence;
				const seqValid =
					Number.isSafeInteger(curSeq) &&
					Number.isSafeInteger(prevSeq) &&
					curSeq === prevSeq + 1;
				results.push({
					index: i,
					receiptId: receipt.id,
					signatureValid,
					hashLinkValid: false,
					sequenceValid: seqValid,
				});
				return {
					valid: false,
					length: receipts.length,
					receipts: results,
					brokenAt: i,
					error: `hash compute failed at index ${i - 1}: ${reason}`,
				};
			}
			hashLinkValid = chain.previous_receipt_hash === previousHash;
		}

		let sequenceValid: boolean;
		const currentSequence = chain.sequence;
		if (!Number.isSafeInteger(currentSequence)) {
			sequenceValid = false;
		} else if (previous === undefined) {
			sequenceValid = currentSequence >= 1;
		} else {
			const prevSequence = previous.credentialSubject.chain.sequence;
			sequenceValid =
				Number.isSafeInteger(prevSequence) &&
				currentSequence === prevSequence + 1;
		}

		results.push({
			index: i,
			receiptId: receipt.id,
			signatureValid,
			hashLinkValid,
			sequenceValid,
		});

		if (
			brokenAt === -1 &&
			(!signatureValid || !hashLinkValid || !sequenceValid)
		) {
			brokenAt = i;
		}

		previous = receipt;
	}

	// Receipt-after-terminal integrity check (unconditional — spec §7.3.2).
	for (let i = 0; i < receipts.length - 1; i++) {
		const r = receipts[i];
		if (r && r.credentialSubject.chain.terminal === true) {
			// A receipt exists after a terminal one — protocol violation.
			if (brokenAt === -1) brokenAt = i + 1;
			return {
				valid: false,
				length: receipts.length,
				receipts: results,
				brokenAt,
				responseHashNote: undefined,
			};
		}
	}

	const cv: ChainVerification = {
		valid: brokenAt === -1,
		length: receipts.length,
		receipts: results,
		brokenAt,
	};

	// Response-hash verification (spec §4.3.2).
	// When a body is supplied: recompute and fail on mismatch.
	// When the body is absent: emit an informational note only.
	for (let i = 0; i < receipts.length; i++) {
		const r = receipts[i];
		if (!r) continue;
		const expectedHash = r.credentialSubject.outcome.response_hash;
		if (!expectedHash) continue;

		const body = options?.responseBodies?.[r.id];
		if (body === undefined) {
			cv.responseHashNote =
				"response_hash present in one or more receipts; response body not supplied — hash cannot be verified offline";
			continue;
		}
		if (!cv.valid) continue;

		const computed = sha256(canonicalize(body));
		if (computed !== expectedHash) {
			return {
				...cv,
				valid: false,
				brokenAt: i,
				error: `response_hash mismatch at index ${i}: receipt has ${expectedHash}, body hashes to ${computed}`,
			};
		}
	}

	if (!cv.valid) return cv;

	// Optional out-of-band checks (only when basic verification passes).
	if (
		options?.expectedLength !== undefined &&
		receipts.length !== options.expectedLength
	) {
		return {
			...cv,
			valid: false,
			brokenAt: receipts.length - 1,
		};
	}

	if (options?.expectedFinalHash !== undefined) {
		const lastReceipt = receipts[receipts.length - 1];
		if (!lastReceipt) {
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
			};
		}
		let lastHash: string;
		try {
			lastHash = hashReceipt(lastReceipt);
		} catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
				error: `hash compute failed at index ${receipts.length - 1}: ${reason}`,
			};
		}
		if (lastHash !== options.expectedFinalHash) {
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
				error: "final receipt hash does not match expected value",
			};
		}
	}

	if (options?.requireTerminal) {
		const lastReceipt = receipts[receipts.length - 1];
		if (!lastReceipt || lastReceipt.credentialSubject.chain.terminal !== true) {
			return {
				...cv,
				valid: false,
				brokenAt: receipts.length - 1,
			};
		}
	}

	return cv;
}
