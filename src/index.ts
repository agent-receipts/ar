export const VERSION = "0.1.0";

export {
	type ChainVerification,
	type ReceiptVerification,
	verifyChain,
} from "./receipt/chain.js";

export { type CreateReceiptInput, createReceipt } from "./receipt/create.js";
export { canonicalize, hashReceipt, sha256 } from "./receipt/hash.js";
export {
	generateKeyPair,
	type KeyPair,
	signReceipt,
	verifyReceipt,
} from "./receipt/signing.js";
// Backwards compatibility aliases (deprecated, use AgentReceipt/UnsignedAgentReceipt)
export type {
	AgentReceipt as ActionReceipt,
	UnsignedAgentReceipt as UnsignedActionReceipt,
} from "./receipt/types.js";
export {
	type Action,
	type ActionTarget,
	type AgentReceipt,
	type Authorization,
	type Chain,
	CONTEXT,
	CREDENTIAL_TYPE,
	type CredentialSubject,
	type Intent,
	type Issuer,
	type Operator,
	type Outcome,
	type OutcomeStatus,
	type Principal,
	type Proof,
	type RiskLevel,
	type StateChange,
	type UnsignedAgentReceipt,
	VERSION as RECEIPT_VERSION,
} from "./receipt/types.js";

export {
	openStore,
	type ReceiptQuery,
	ReceiptStore,
	type StoreStats,
} from "./store/store.js";
export { verifyStoredChain } from "./store/verify.js";
export {
	ALL_ACTIONS,
	FILESYSTEM_ACTIONS,
	getActionType,
	resolveActionType,
	SYSTEM_ACTIONS,
	UNKNOWN_ACTION,
} from "./taxonomy/actions.js";
export {
	type ClassificationResult,
	classifyToolCall,
} from "./taxonomy/classify.js";
export {
	loadTaxonomyConfig,
	type TaxonomyConfig,
} from "./taxonomy/config.js";
export type {
	ActionTypeEntry,
	TaxonomyMapping,
} from "./taxonomy/types.js";
