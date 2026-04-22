"""Receipt creation — build unsigned Agent Receipts from structured inputs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from agent_receipts.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
    Action,
    Authorization,
    Chain,
    CredentialSubject,
    Intent,
    Issuer,
    Outcome,
    Principal,
    UnsignedAgentReceipt,
)


def _utc_now_iso() -> str:
    """Generate an ISO 8601 timestamp matching JS ``new Date().toISOString()``."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


class ActionInput(BaseModel):
    """Action fields for receipt creation (id and timestamp auto-generated)."""

    type: str
    risk_level: str
    target: Any = None  # noqa: ANN401
    parameters_hash: str | None = None
    trusted_timestamp: str | None = None


class CreateReceiptInput(BaseModel):
    """Inputs for creating an unsigned receipt."""

    issuer: Issuer
    principal: Principal
    action: ActionInput
    outcome: Outcome
    chain: Chain
    intent: Intent | None = None
    authorization: Authorization | None = None
    action_timestamp: str | None = None
    response_body: Any = None  # noqa: ANN401  # any JSON value, not just objects
    terminal: bool = False


def create_receipt(input: CreateReceiptInput) -> UnsignedAgentReceipt:
    """Build an unsigned Agent Receipt from structured inputs.

    Auto-generates: receipt id (URN UUID), action id, issuanceDate,
    action timestamp, @context, type, and version.
    """
    now = _utc_now_iso()
    action_timestamp = input.action_timestamp or now

    # Build action dict, excluding None values
    action_data: dict[str, Any] = {
        "id": f"act_{uuid.uuid4()}",
        "type": input.action.type,
        "risk_level": input.action.risk_level,
        "timestamp": action_timestamp,
    }
    if input.action.target is not None:
        action_data["target"] = input.action.target
    if input.action.parameters_hash is not None:
        action_data["parameters_hash"] = input.action.parameters_hash
    if input.action.trusted_timestamp is not None:
        action_data["trusted_timestamp"] = input.action.trusted_timestamp

    # Compute response_hash when a response body is supplied.
    if input.response_body is not None:
        from agent_receipts.receipt.hash import canonicalize, sha256

        canonical = canonicalize(input.response_body)
        response_hash = sha256(canonical)
        # Merge into outcome
        outcome_with_hash = Outcome(
            **input.outcome.model_dump(exclude={"response_hash"}),
            response_hash=response_hash,
        )
    else:
        outcome_with_hash = input.outcome

    # Set terminal marker (never set False).
    # exclude_none=True strips terminal: null (desired) but also drops
    # previous_receipt_hash: null for the first receipt in a chain.
    # Re-add it explicitly because Chain requires the field (no default).
    chain_data = input.chain.model_dump(exclude_none=True)
    if "previous_receipt_hash" not in chain_data:
        chain_data["previous_receipt_hash"] = None
    if input.terminal:
        chain_data["terminal"] = True
    chain_with_terminal = Chain(**chain_data)

    # Build credential subject
    cs_data: dict[str, Any] = {
        "principal": input.principal,
        "action": Action(**action_data),
        "outcome": outcome_with_hash,
        "chain": chain_with_terminal,
    }
    if input.intent is not None:
        cs_data["intent"] = input.intent
    if input.authorization is not None:
        cs_data["authorization"] = input.authorization

    receipt_data: dict[str, Any] = {
        "@context": list(CONTEXT),
        "id": f"urn:receipt:{uuid.uuid4()}",
        "type": list(CREDENTIAL_TYPE),
        "version": VERSION,
        "issuer": input.issuer,
        "issuanceDate": now,
        "credentialSubject": CredentialSubject(**cs_data),
    }
    return UnsignedAgentReceipt.model_validate(receipt_data)
