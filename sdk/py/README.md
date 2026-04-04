<div align="center">

# agent-receipts

### Python SDK for the Agent Receipts protocol

[![PyPI](https://img.shields.io/pypi/v/agent-receipts)](https://pypi.org/project/agent-receipts/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/agent-receipts/sdk-py/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-receipts/sdk-py/actions/workflows/ci.yml)

---

Create, sign, hash-chain, store, and verify cryptographically signed audit trails for AI agent actions.

[Spec](https://github.com/agent-receipts/spec) &bull; [TypeScript SDK](https://github.com/agent-receipts/sdk-ts) &bull; [Reference Implementation](https://github.com/ojongerius/attest)

</div>

---

## Why receipts?

If you're building with AI agents, you're probably already logging what they do. Receipts go further: they're **cryptographically signed, hash-chained records** that can't be quietly altered after the fact — and they follow a standard format that works across languages, agents, and systems.

Here's where that matters in practice:

- **Post-incident review** — An agent ran overnight and something broke. The receipt chain shows exactly which actions it took, in what order, and whether each succeeded or failed — with cryptographic proof the log hasn't been tampered with after the fact.

- **Compliance and audit** — Regulated environments require evidence of what systems did and why. Receipts are W3C Verifiable Credentials with Ed25519 signatures, giving auditors a tamper-evident trail they can independently verify.

- **Safer autonomous agents** — Agents can query their own audit trail mid-session. Before taking a high-risk action, an agent can check what it has already done and whether previous steps succeeded, enabling self-correcting workflows.

- **Multi-agent trust** — When agents collaborate, receipts serve as proof of prior actions. Agent B can verify that Agent A actually completed step 1 before proceeding to step 2, without trusting a shared log.

- **Usage tracking** — Every action is classified by type and risk level, giving you a structured breakdown of what agents spent their time on.

### Beyond local storage

The protocol is designed for receipts to travel — publishing to a shared ledger, forwarding to a compliance system, or exchanging between agents as proof of prior actions. Receipts are portable W3C Verifiable Credentials, but where they go is always under the user's control.

---

## Install

```sh
pip install agent-receipts
```

## Quick start

### Create and sign a receipt

```python
from agent_receipts import (
    create_receipt,
    generate_key_pair,
    hash_receipt,
    sign_receipt,
    CreateReceiptInput,
    Chain,
    Issuer,
    Outcome,
    Principal,
)
from agent_receipts.receipt.create import ActionInput

# Generate an Ed25519 key pair
keys = generate_key_pair()

# Create an unsigned receipt
unsigned = create_receipt(CreateReceiptInput(
    issuer=Issuer(id="did:agent:my-agent"),
    principal=Principal(id="did:user:alice"),
    action=ActionInput(
        type="filesystem.file.read",
        risk_level="low",
    ),
    outcome=Outcome(status="success"),
    chain=Chain(
        sequence=1,
        previous_receipt_hash=None,
        chain_id="chain_session-1",
    ),
))

# Sign and hash
receipt = sign_receipt(unsigned, keys.private_key, "did:agent:my-agent#key-1")
receipt_hash = hash_receipt(receipt)
```

### Verify a receipt

```python
from agent_receipts import verify_receipt

valid = verify_receipt(receipt, keys.public_key)
print(f"Signature valid: {valid}")  # True
```

### Verify a chain

```python
from agent_receipts import verify_chain

# Verify a list of receipts (e.g. [receipt] from the example above)
result = verify_chain([receipt], keys.public_key)
print(f"Chain valid: {result.valid}")
print(f"Receipts verified: {result.length}")
if not result.valid:
    print(f"Broken at index: {result.broken_at}")
```

### Action taxonomy

The standardized action taxonomy (action types and risk levels) is defined in the
[protocol specification](https://github.com/agent-receipts/spec/tree/main/spec/taxonomy).
Taxonomy classification will be added in a future milestone (M3).

## What is an Agent Receipt?

A [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/) signed with Ed25519, recording:

| Field | What it captures |
|:---|:---|
| **Action** | What happened, classified by a [standardized taxonomy](https://github.com/agent-receipts/spec/tree/main/spec/taxonomy) |
| **Principal** | Who authorized it (human or organization) |
| **Issuer** | Which agent performed it |
| **Outcome** | Success/failure, reversibility, undo method |
| **Chain** | SHA-256 hash link to the previous receipt (tamper-evident) |
| **Privacy** | Parameters are hashed, never stored in plaintext |

## API reference

### Receipt creation and signing

```python
from agent_receipts import (
    create_receipt,       # Build an unsigned receipt from input fields
    generate_key_pair,    # Ed25519 key pair (PEM-encoded)
    sign_receipt,         # Sign with Ed25519Signature2020 proof
    verify_receipt,       # Verify a receipt's signature
)
```

### Hashing and canonicalization

```python
from agent_receipts import (
    canonicalize,         # RFC 8785 JSON canonicalization
    hash_receipt,         # Hash receipt (excluding proof) -> "sha256:<hex>"
    sha256,               # Hash arbitrary data -> "sha256:<hex>"
)
```

### Chain verification

```python
from agent_receipts import (
    verify_chain,         # Verify signatures, hash links, and sequence numbering
)
```

### Types (Pydantic v2 models)

```python
from agent_receipts import (
    ActionReceipt,        # Signed receipt with proof
    UnsignedActionReceipt,  # Receipt before signing
    Action, ActionTarget, Authorization, Chain,
    CredentialSubject, Intent, Issuer, Operator,
    Outcome, Principal, Proof, StateChange,
)
```

### Subpackage imports

```python
from agent_receipts.receipt import create_receipt, sign_receipt
from agent_receipts.receipt.hash import canonicalize
from agent_receipts.receipt.types import CONTEXT, CREDENTIAL_TYPE
```

### TypeScript SDK compatibility

camelCase aliases are available for users coming from the TS SDK:

```python
from agent_receipts import (
    createReceipt,    # = create_receipt
    generateKeyPair,  # = generate_key_pair
    signReceipt,      # = sign_receipt
    verifyReceipt,    # = verify_receipt
    hashReceipt,      # = hash_receipt
    verifyChain,      # = verify_chain
)
```

## Cross-language compatibility

This SDK produces **byte-identical** output to [`@agnt-rcpt/sdk-ts`](https://github.com/agent-receipts/sdk-ts):

- RFC 8785 canonical JSON matches exactly
- SHA-256 hashes are identical
- Ed25519 signatures from either SDK verify in the other

Cross-language compatibility is verified by test vectors generated from the TypeScript SDK.

## Project structure

```
src/agent_receipts/
  receipt/
    types.py       # Pydantic models for all receipt types
    create.py      # Receipt creation with auto-generated IDs
    signing.py     # Ed25519 signing and verification
    hash.py        # RFC 8785 canonicalization + SHA-256
    chain.py       # Chain verification
```

## Development

```sh
uv sync --all-extras
uv run pytest              # run tests
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pyright             # type check
```

| | |
|:---|:---|
| **Language** | Python 3.11+ |
| **Types** | Pydantic v2, pyright strict mode |
| **Linting** | ruff |
| **Testing** | pytest |
| **Dependencies** | `pydantic>=2.0`, `cryptography>=41.0` |

## Ecosystem

| Repository | Description |
|:---|:---|
| [agent-receipts/spec](https://github.com/agent-receipts/spec) | Protocol specification, JSON Schemas, canonical taxonomy |
| [agent-receipts/sdk-ts](https://github.com/agent-receipts/sdk-ts) | TypeScript SDK ([npm](https://www.npmjs.com/package/@agnt-rcpt/sdk-ts)) |
| **agent-receipts/sdk-py** (this package) | Python SDK |
| [ojongerius/attest](https://github.com/ojongerius/attest) | MCP proxy + CLI (reference implementation) |

## License

Apache 2.0 — see [LICENSE](LICENSE).
