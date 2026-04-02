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
    VERSION,
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

# Backwards compatibility aliases (deprecated)
ActionReceipt = AgentReceipt
UnsignedActionReceipt = UnsignedAgentReceipt

__all__ = [
    # Types
    "Action",
    "ActionReceipt",
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
    "UnsignedActionReceipt",
    "UnsignedAgentReceipt",
    # Constants
    "CONTEXT",
    "CREDENTIAL_TYPE",
    "VERSION",
    # Creation
    "CreateReceiptInput",
    "create_receipt",
    # Hashing
    "canonicalize",
    "hash_receipt",
    "sha256",
    # Signing
    "KeyPair",
    "generate_key_pair",
    "sign_receipt",
    "verify_receipt",
    # Chain
    "ChainVerification",
    "ReceiptVerification",
    "verify_chain",
]
