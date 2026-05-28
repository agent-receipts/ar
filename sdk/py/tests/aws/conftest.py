"""Test helpers for the AWS KMS signer.

``MockKMSClient`` is a hand-written stand-in for a boto3 ``kms`` client, backed
by an in-test Ed25519 key so a signature produced by ``sign`` verifies against
the key returned by ``get_public_key`` — mirroring the Go SDK's ``mockKMS``.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


class MockKMSClient:
    def __init__(self) -> None:
        self._priv = Ed25519PrivateKey.generate()
        self.pub = self._priv.public_key()
        self.sign_calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.get_pub_calls = 0
        self.sign_hook: Callable[[dict[str, Any]], Mapping[str, Any]] | None = None
        self.get_pub_hook: Callable[[str], Mapping[str, Any]] | None = None

    def raw_public_key(self) -> bytes:
        return self.pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def spki_der(self) -> bytes:
        return self.pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def sign(
        self,
        *,
        KeyId: str,
        Message: bytes,
        SigningAlgorithm: str,
        MessageType: str,
    ) -> Mapping[str, Any]:
        call = {
            "KeyId": KeyId,
            "Message": Message,
            "SigningAlgorithm": SigningAlgorithm,
            "MessageType": MessageType,
        }
        self.sign_calls.append(call)
        if self.sign_hook is not None:
            return self.sign_hook(call)
        return {
            "Signature": self._priv.sign(Message),
            "SigningAlgorithm": SigningAlgorithm,
        }

    def get_public_key(self, *, KeyId: str) -> Mapping[str, Any]:
        with self._lock:
            self.get_pub_calls += 1
        if self.get_pub_hook is not None:
            return self.get_pub_hook(KeyId)
        return {"PublicKey": self.spki_der(), "KeySpec": "ECC_NIST_EDWARDS25519"}
