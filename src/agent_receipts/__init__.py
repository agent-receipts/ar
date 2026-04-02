"""Python SDK for the Agent Receipts protocol."""

from agent_receipts._version import VERSION
from agent_receipts.receipt.chain import (
    ChainVerification,
    ReceiptVerification,
    verify_chain,
)
from agent_receipts.receipt.create import CreateReceiptInput, create_receipt
from agent_receipts.receipt.hash import canonicalize, hash_receipt, sha256
from agent_receipts.receipt.signing import (
    KeyPair,
    generate_key_pair,
    sign_receipt,
    verify_receipt,
)
from agent_receipts.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    Action,
    ActionTarget,
    AgentReceipt,
    Authorization,
    Chain,
    CredentialSubject,
    Intent,
    Issuer,
    Operator,
    Outcome,
    Principal,
    Proof,
    StateChange,
    UnsignedAgentReceipt,
)
from agent_receipts.store.store import (
    ReceiptQuery,
    ReceiptStore,
    StoreStats,
    open_store,
)
from agent_receipts.store.verify import verify_stored_chain
from agent_receipts.taxonomy.actions import (
    ALL_ACTIONS,
    FILESYSTEM_ACTIONS,
    SYSTEM_ACTIONS,
    UNKNOWN_ACTION,
    get_action_type,
    resolve_action_type,
)
from agent_receipts.taxonomy.classify import ClassificationResult, classify_tool_call
from agent_receipts.taxonomy.config import load_taxonomy_config
from agent_receipts.taxonomy.types import ActionTypeEntry, TaxonomyMapping

# Backwards compatibility aliases (deprecated, use AgentReceipt/UnsignedAgentReceipt)
ActionReceipt = AgentReceipt
UnsignedActionReceipt = UnsignedAgentReceipt

# camelCase aliases for users coming from the TypeScript SDK
createReceipt = create_receipt
generateKeyPair = generate_key_pair
signReceipt = sign_receipt
verifyReceipt = verify_receipt
hashReceipt = hash_receipt
verifyChain = verify_chain
openStore = open_store
verifyStoredChain = verify_stored_chain
classifyToolCall = classify_tool_call
getActionType = get_action_type
resolveActionType = resolve_action_type
loadTaxonomyConfig = load_taxonomy_config

# RECEIPT_VERSION is the receipt schema version (from types), not the package version
from agent_receipts.receipt.types import VERSION as RECEIPT_VERSION  # noqa: E402

__all__ = [
    # Version
    "VERSION",
    "RECEIPT_VERSION",
    # Types
    "Action",
    "AgentReceipt",
    "ActionTarget",
    "Authorization",
    "Chain",
    "CredentialSubject",
    "Intent",
    "Issuer",
    "Operator",
    "Outcome",
    "Principal",
    "Proof",
    "StateChange",
    "UnsignedAgentReceipt",
    # Backwards compat aliases (deprecated)
    "ActionReceipt",
    "UnsignedActionReceipt",
    # Constants
    "CONTEXT",
    "CREDENTIAL_TYPE",
    # Creation
    "CreateReceiptInput",
    "create_receipt",
    "createReceipt",
    # Hashing
    "canonicalize",
    "hash_receipt",
    "hashReceipt",
    "sha256",
    # Signing
    "KeyPair",
    "generate_key_pair",
    "generateKeyPair",
    "sign_receipt",
    "signReceipt",
    "verify_receipt",
    "verifyReceipt",
    # Chain
    "ChainVerification",
    "ReceiptVerification",
    "verify_chain",
    "verifyChain",
    # Store
    "ReceiptQuery",
    "ReceiptStore",
    "StoreStats",
    "open_store",
    "openStore",
    "verify_stored_chain",
    "verifyStoredChain",
    # Taxonomy
    "ALL_ACTIONS",
    "ActionTypeEntry",
    "ClassificationResult",
    "FILESYSTEM_ACTIONS",
    "SYSTEM_ACTIONS",
    "TaxonomyMapping",
    "UNKNOWN_ACTION",
    "classify_tool_call",
    "classifyToolCall",
    "get_action_type",
    "getActionType",
    "load_taxonomy_config",
    "loadTaxonomyConfig",
    "resolve_action_type",
    "resolveActionType",
]
