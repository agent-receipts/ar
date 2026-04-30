"""Agent Receipt schema types.

These types model the Attest Agent Receipt as a W3C Verifiable Credential.
Both the full and minimal receipt variants share the same type — optional
fields are marked with ``None`` defaults.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CONTEXT: list[str] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentreceipts.ai/context/v1",
]

CREDENTIAL_TYPE: list[str] = [
    "VerifiableCredential",
    "AgentReceipt",
]

VERSION = "0.2.0"

RiskLevel = Literal["low", "medium", "high", "critical"]

OutcomeStatus = Literal["success", "failure", "pending"]


class Operator(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str


class Issuer(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str | None = None
    name: str | None = None
    operator: Operator | None = None
    model: str | None = None
    session_id: str | None = None


class Principal(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str | None = None


class ActionTarget(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    system: str
    resource: str | None = None


class Action(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str
    tool_name: str | None = None
    risk_level: RiskLevel
    target: ActionTarget | None = None
    parameters_hash: str | None = None
    parameters_disclosure: dict[str, str] | None = None
    timestamp: str
    trusted_timestamp: str | None = None


class Intent(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    conversation_hash: str | None = None
    prompt_preview: str | None = None
    prompt_preview_truncated: bool | None = None
    reasoning_hash: str | None = None


class StateChange(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    before_hash: str
    after_hash: str


class Outcome(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    status: OutcomeStatus
    error: str | None = None
    reversible: bool | None = None
    reversal_method: str | None = None
    reversal_window_seconds: int | None = None
    state_change: StateChange | None = None
    response_hash: str | None = None


class Authorization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    scopes: list[str]
    granted_at: str
    expires_at: str | None = None
    grant_ref: str | None = None


class Chain(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sequence: int
    previous_receipt_hash: str | None
    chain_id: str
    terminal: Literal[True] | None = None


class CredentialSubject(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal: Principal
    action: Action
    intent: Intent | None = None
    outcome: Outcome
    authorization: Authorization | None = None
    chain: Chain


class Proof(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: str
    created: str | None = None
    verificationMethod: str | None = None  # noqa: N815
    proofPurpose: str | None = None  # noqa: N815
    proofValue: str  # noqa: N815


class UnsignedAgentReceipt(BaseModel):
    """An Agent Receipt before signing — no proof field yet."""

    model_config = ConfigDict(populate_by_name=True)

    context: list[str] = Field(alias="@context")
    id: str
    type: list[str]
    version: str
    issuer: Issuer
    issuanceDate: str  # noqa: N815
    credentialSubject: CredentialSubject  # noqa: N815


class AgentReceipt(UnsignedAgentReceipt):
    """A signed Agent Receipt with Ed25519 proof."""

    proof: Proof


# Backwards compatibility aliases (deprecated)
ActionReceipt = AgentReceipt
UnsignedActionReceipt = UnsignedAgentReceipt
