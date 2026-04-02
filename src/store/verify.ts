import type { ChainVerification } from "../receipt/chain.js";
import { verifyChain } from "../receipt/chain.js";
import type { ReceiptStore } from "./store.js";

/**
 * Load a chain from the store and verify its integrity.
 *
 * Checks Ed25519 signatures, hash linkage, and sequence ordering
 * for all receipts in the given chain.
 */
export function verifyStoredChain(
	store: ReceiptStore,
	chainId: string,
	publicKey: string,
): ChainVerification {
	const receipts = store.getChain(chainId);
	return verifyChain(receipts, publicKey);
}
