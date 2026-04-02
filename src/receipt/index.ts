export {
	type ChainVerification,
	type ReceiptVerification,
	verifyChain,
} from "./chain.js";
export { type CreateReceiptInput, createReceipt } from "./create.js";
export { canonicalize, hashReceipt, sha256 } from "./hash.js";
export {
	generateKeyPair,
	type KeyPair,
	signReceipt,
	verifyReceipt,
} from "./signing.js";
// Backwards compatibility aliases (deprecated, use AgentReceipt/UnsignedAgentReceipt)
export type {
	AgentReceipt as ActionReceipt,
	UnsignedAgentReceipt as UnsignedActionReceipt,
} from "./types.js";
export {
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
	VERSION,
} from "./types.js";
