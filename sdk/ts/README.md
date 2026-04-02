<div align="center">

# @agent-receipts/sdk-ts

### TypeScript SDK for the Agent Receipts protocol

[![npm](https://img.shields.io/npm/v/@agent-receipts/sdk-ts)](https://www.npmjs.com/package/@agent-receipts/sdk-ts)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ESM-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-22+-339933?logo=node.js&logoColor=white)](https://nodejs.org/)

---

Create, sign, hash-chain, store, and verify cryptographically signed audit trails for AI agent actions.

Zero runtime dependencies — uses only `node:crypto` and `node:sqlite`.

[Spec](https://github.com/agent-receipts/spec) &bull; [Reference Implementation](https://github.com/ojongerius/attest) &bull; [npm](https://www.npmjs.com/package/@agent-receipts/sdk-ts)

</div>

---

## Why receipts?

AI agents that read files, run commands, and browse the web are powerful — but that power needs accountability. When an agent operates autonomously, you need to know exactly what it did, prove that the record hasn't been tampered with, and keep sensitive details private.

**Use cases:**

- **Post-incident review** — an agent ran overnight and something broke. The receipt chain shows exactly which actions it took, in what order, and whether each succeeded or failed — with cryptographic proof the log hasn't been altered after the fact.
- **Compliance and audit** — regulated environments require evidence of what systems did and why. Receipts are W3C Verifiable Credentials with Ed25519 signatures, giving auditors a tamper-evident trail they can independently verify.
- **Safer autonomous agents** — agents can query their own audit trail mid-session. Before taking a high-risk action, they can check what they've already done and whether previous steps succeeded, enabling self-correcting workflows.
- **Multi-agent trust** — when agents collaborate, receipts serve as proof of prior actions. Agent B can verify that Agent A actually completed step 1 before proceeding to step 2, without trusting a shared log.
- **Usage tracking** — every action is classified by type and risk level, giving you a structured breakdown of what agents spent their time on.

### Beyond local storage

Today, this SDK stores receipts locally in SQLite — fully under your control. The [Agent Receipts protocol](https://github.com/agent-receipts/ar/tree/main/spec) is designed for receipts to travel further when you choose: publishing to a shared ledger, forwarding to a compliance system, or exchanging between agents as proof of prior actions. The receipts are portable W3C Verifiable Credentials, but where they go is always your decision.

## Install

```sh
npm install @agent-receipts/sdk-ts
```

## Quick start

### Create and sign a receipt

```typescript
import {
  createReceipt,
  generateKeyPair,
  hashReceipt,
  signReceipt,
} from "@agent-receipts/sdk-ts";

// Generate an Ed25519 key pair
const keys = generateKeyPair();

// Create an unsigned receipt
const unsigned = createReceipt({
  issuer: { id: "did:agent:my-agent" },
  principal: { id: "did:user:alice" },
  action: {
    type: "filesystem.file.read",
    risk_level: "low",
    target: { system: "local", resource: "/docs/report.md" },
  },
  outcome: { status: "success" },
  chain: {
    sequence: 1,
    previous_receipt_hash: null,
    chain_id: "chain_session-1",
  },
});

// Sign and hash
const receipt = signReceipt(unsigned, keys.privateKey, "did:agent:my-agent#key-1");
const hash = hashReceipt(receipt);
```

### Store and query

```typescript
import { openStore } from "@agent-receipts/sdk-ts";

const store = openStore("receipts.db");
store.insert(receipt, hash);

// Query by chain
const chain = store.getChain("chain_session-1");

// Query with filters
const highRisk = store.query({ riskLevel: "high", status: "success" });

// Summary statistics
const stats = store.stats();

store.close();
```

### Verify a chain

```typescript
import { verifyChain, verifyStoredChain } from "@agent-receipts/sdk-ts";

// Verify an array of receipts
const result = verifyChain(receipts, publicKey);
console.log(result.valid);          // true if all signatures and hash links check out
console.log(result.length);         // number of receipts verified

// Or verify directly from the store
const storeResult = verifyStoredChain(store, "chain_session-1", publicKey);
```

### Classify tool calls

```typescript
import { classifyToolCall, loadTaxonomyConfig } from "@agent-receipts/sdk-ts";

// Built-in classification
const result = classifyToolCall("read_file");
// → { action_type: "unknown", risk_level: "medium" }

// With custom mappings
const mappings = loadTaxonomyConfig("taxonomy.json");
const mapped = classifyToolCall("read_file", mappings);
// → { action_type: "filesystem.file.read", risk_level: "low" }
```

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

```typescript
import {
  createReceipt,       // Build an unsigned receipt from input fields
  generateKeyPair,     // Ed25519 key pair (PEM-encoded)
  signReceipt,         // Sign with Ed25519Signature2020 proof
  verifyReceipt,       // Verify a single receipt's signature
} from "@agent-receipts/sdk-ts";
```

### Hashing and canonicalization

```typescript
import {
  canonicalize,        // RFC 8785 JSON canonicalization
  hashReceipt,         // Hash receipt (excluding proof) → "sha256:<hex>"
  sha256,              // Hash arbitrary data → "sha256:<hex>"
} from "@agent-receipts/sdk-ts";
```

### Chain verification

```typescript
import {
  verifyChain,         // Verify signatures, hash links, and sequence numbering
} from "@agent-receipts/sdk-ts";
```

### Storage (SQLite)

```typescript
import {
  openStore,           // Open or create a receipt store
  ReceiptStore,        // Insert, query, get by ID, get chain, stats
  verifyStoredChain,   // Load a chain from store and verify integrity
} from "@agent-receipts/sdk-ts";
```

### Taxonomy

```typescript
import {
  classifyToolCall,    // Map tool names → action types + risk levels
  loadTaxonomyConfig,  // Load tool→action mappings from a JSON config file
  ALL_ACTIONS,         // All 15 built-in action types
  resolveActionType,   // Look up action type with fallback to "unknown"
} from "@agent-receipts/sdk-ts";
```

### Subpath imports

For more targeted imports:

```typescript
import { createReceipt, signReceipt } from "@agent-receipts/sdk-ts/receipt";
import { openStore } from "@agent-receipts/sdk-ts/store";
import { classifyToolCall } from "@agent-receipts/sdk-ts/taxonomy";
```

## Project structure

```
src/
  receipt/      # Receipt creation, Ed25519 signing, RFC 8785 hashing, chain verification
  store/        # SQLite persistence and chain integrity verification
  taxonomy/     # Action type classification (15 types) + config file loading
```

## Development

```sh
pnpm install
pnpm run test          # 101 tests
pnpm run check         # typecheck + lint
pnpm run build         # compile to dist/
```

| | |
|:---|:---|
| **Language** | TypeScript ESM, strict mode |
| **Linting** | Biome (tabs, double quotes) |
| **Testing** | Vitest (colocated `*.test.ts` files) |
| **Runtime deps** | Zero — `node:crypto` and `node:sqlite` only |

## Ecosystem

| Repository | Description |
|:---|:---|
| [agent-receipts/spec](https://github.com/agent-receipts/spec) | Protocol specification, JSON Schemas, canonical taxonomy |
| **@agent-receipts/sdk-ts** (this package) | TypeScript SDK |
| [ojongerius/attest](https://github.com/ojongerius/attest) | MCP proxy + CLI (reference implementation, consumes this SDK) |
| [agent-receipts/sdk-py](https://github.com/agent-receipts/sdk-py) | Python SDK ([PyPI](https://pypi.org/project/agent-receipts/)) |

## License

Apache 2.0 — see [LICENSE](LICENSE).
