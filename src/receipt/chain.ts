import { hashReceipt } from "./hash.js";
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
}

/**
 * Verify a chain of signed receipts.
 *
 * Checks for each receipt:
 * 1. Ed25519 signature validity
 * 2. Hash linkage: previous_receipt_hash matches SHA-256 of prior receipt
 * 3. Sequence numbers are strictly incrementing
 *
 * Receipts must be provided in chain order (by sequence number).
 */
export function verifyChain(
	receipts: AgentReceipt[],
	publicKey: string,
): ChainVerification {
	if (receipts.length === 0) {
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
			const previousHash = hashReceipt(previous);
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

		const verification: ReceiptVerification = {
			index: i,
			receiptId: receipt.id,
			signatureValid,
			hashLinkValid,
			sequenceValid,
		};

		results.push(verification);

		if (
			brokenAt === -1 &&
			(!signatureValid || !hashLinkValid || !sequenceValid)
		) {
			brokenAt = i;
		}

		previous = receipt;
	}

	return {
		valid: brokenAt === -1,
		length: receipts.length,
		receipts: results,
		brokenAt,
	};
}
