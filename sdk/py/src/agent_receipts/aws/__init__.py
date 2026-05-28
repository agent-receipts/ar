"""AWS adapters for the Agent Receipts SDK.

Requires the optional ``aws`` extra: ``pip install agent-receipts[aws]``.
"""

from __future__ import annotations

from agent_receipts.aws.kms import KMSClient, KMSSigner, KMSSignerError, Signer

__all__ = ["KMSClient", "KMSSigner", "KMSSignerError", "Signer"]
