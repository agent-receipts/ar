"""RFC 8785 JSON canonicalization and SHA-256 hashing."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _utf16_sort_key(s: str) -> list[int]:
    """Sort key using UTF-16 code unit order per RFC 8785.

    For BMP characters (all ASCII keys), this is identical to Unicode code
    point order. For non-BMP characters, surrogate pairs are compared by
    their UTF-16 code units rather than code points.
    """
    return list(s.encode("utf-16-le"))


def canonicalize(value: Any) -> str:  # noqa: ANN401
    """Serialize a value to canonical JSON per RFC 8785.

    Key rules:
    - Object keys are sorted lexicographically
    - Numbers use shortest representation
    - No whitespace between tokens
    - Strings use minimal escaping
    - null, boolean, and string values serialized per JSON spec
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonicalize_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_sort_key)
        entries = [
            f"{json.dumps(k, ensure_ascii=False)}:{canonicalize(value[k])}"
            for k in keys
        ]
        return "{" + ",".join(entries) + "}"
    msg = f"RFC 8785: unsupported type: {type(value).__name__}"
    raise TypeError(msg)


def _canonicalize_number(n: float) -> str:
    """RFC 8785 number serialization matching ES Number.toString().

    Produces the shortest round-trippable representation with ES-compatible
    exponent formatting (e.g. ``1e-6`` not ``1e-06``).
    """
    if not math.isfinite(n):
        msg = f"RFC 8785: non-finite numbers are not valid JSON: {n}"
        raise ValueError(msg)
    if n == 0.0:
        return "0"
    # For integers represented as float, strip the decimal
    if n == int(n) and abs(n) < 2**53:
        return str(int(n))
    # Use repr for shortest representation, then normalize exponent
    # to match ES format (e.g. "1e-06" -> "1e-6", "1e+02" -> "1e+2")
    s = repr(n)
    if "e" in s:
        mantissa, exp = s.split("e")
        sign = exp[0] if exp[0] in "+-" else "+"
        digits = exp.lstrip("+-").lstrip("0") or "0"
        s = f"{mantissa}e{sign}{digits}"
    return s


def hash_receipt(receipt: Any) -> str:  # noqa: ANN401
    """Compute SHA-256 hash of a receipt, excluding the proof field.

    Accepts either an AgentReceipt Pydantic model or a plain dict.
    Returns the hash in ``sha256:<hex>`` format.
    """
    from agent_receipts.receipt.types import AgentReceipt

    if isinstance(receipt, AgentReceipt):
        d = receipt.model_dump(by_alias=True, exclude_none=True)
    elif isinstance(receipt, dict):
        d = dict(receipt)
    else:
        msg = f"Expected AgentReceipt or dict, got {type(receipt).__name__}"
        raise TypeError(msg)

    d.pop("proof", None)

    # Ensure previous_receipt_hash is preserved as null when None
    cs = d.get("credentialSubject", {})
    chain = cs.get("chain", {})
    if "previous_receipt_hash" not in chain:
        chain["previous_receipt_hash"] = None

    canonical = canonicalize(d)
    return sha256(canonical)


def sha256(data: str) -> str:
    """Compute SHA-256 hash of arbitrary data.

    Returns ``sha256:<hex>`` format.
    """
    h = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return f"sha256:{h}"
