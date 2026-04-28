# Receipt Chain Linking and Signing

## Chain hash linking

```mermaid
flowchart LR
  subgraph R1["Receipt 1"]
    r1body["sequence: 1\nprevious_receipt_hash: null"]
  end

  subgraph R2["Receipt 2"]
    r2body["sequence: 2\nprevious_receipt_hash:\nsha256:abc123..."]
  end

  subgraph R3["Receipt 3"]
    r3body["sequence: 3\nprevious_receipt_hash:\nsha256:def456..."]
  end

  r1body -- "SHA-256 of\ncanonical form\n(proof removed)" --> r2body
  r2body -- "SHA-256 of\ncanonical form\n(proof removed)" --> r3body
```

All receipts in a chain share the same `chain_id` and `issuer.id`.

## Signing flow

```mermaid
flowchart TD
  A["Receipt fields\n(proof not yet present)"] --> C["RFC 8785\nJSON Canonicalization"]
  C --> D["Canonical JSON bytes"]
  D --> E["Ed25519 sign\nwith issuer's private key"]
  E --> F["Base64url encode\n(u-prefix, no padding)"]
  F --> G["Attach as\nproof.proofValue"]
  G --> H["Signed Agent Receipt"]

  D --> I["SHA-256 hash"]
  I --> J["sha256:hex\n→ next receipt's\nprevious_receipt_hash"]
```

## Delegation linking

```mermaid
flowchart TD
  subgraph PC["Parent Chain (Agent A)"]
    direction LR
    pr1["Receipt 1"] --> pr2["Receipt 2\n(delegates to Agent B)"] --> pr3["Receipt 3"]
  end

  subgraph DC["Delegated Chain (Agent B)"]
    direction LR
    dr1["Receipt 1\n+ delegation field"] --> dr2["Receipt 2"]
  end

  pr2 -. "delegation.parent_receipt_id" .-> dr1
  dr1 -. "delegation.parent_chain_id\ndelegation.delegator.id" .-> pr2
```

The delegated chain carries a `delegation` field on its first receipt, linking back to the parent chain. Both chains share the same `principal` (the human who authorized the work).
