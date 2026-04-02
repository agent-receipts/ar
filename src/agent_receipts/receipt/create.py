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

    # Build credential subject
    cs_data: dict[str, Any] = {
        "principal": input.principal,
        "action": Action(**action_data),
        "outcome": input.outcome,
        "chain": input.chain,
    }
    if input.intent is not None:
        cs_data["intent"] = input.intent
    if input.authorization is not None:
        cs_data["authorization"] = input.authorization

    return UnsignedAgentReceipt(
        **{
            "@context": list(CONTEXT),
            "id": f"urn:receipt:{uuid.uuid4()}",
            "type": list(CREDENTIAL_TYPE),
            "version": VERSION,
            "issuer": input.issuer,
            "issuanceDate": now,
            "credentialSubject": CredentialSubject(**cs_data),
        }
    )
