# Agent Receipts — Canonical Positioning

This document is the source of truth for how Agent Receipts is described on the
site, in the README, and in any external-facing copy. Downstream audits measure
against this file. Update this file first; everything else follows.

## One-liner

Independent audit trail for agentic AI tool calls — signing keys live outside the agent.

## Value proposition

Security teams block agentic AI features — computer use, browser automation,
MCP-driven workflows — when they cannot see what the agent is doing. Agent
Receipts produces a tamper-evident, independently verifiable record of every
tool call. A separate daemon owns the signing keys and the receipt store; the
agent process never touches them. The result is an audit trail that holds up
even if the agent itself is later compromised. Built for platform and security
teams approving agentic deployments.

## Differentiation

- **Daemon-isolated keys.** The signing keys and receipt store live in a separate OS-level process with peer-credential attestation. A compromised agent cannot forge or suppress its own receipts.
- **W3C Verifiable Credentials envelope.** Receipts are standard W3C VCs, interoperable with existing identity, compliance, and supply-chain tooling — the rest of the space ships custom JSON.
- **Audit, not enforcement.** A passive sink that records what happened. Pairs with any firewall, proxy, or policy engine without overlapping their scope.

## Hero block

- **H1:** An audit trail your agent can't tamper with
- **Subhead:** A separate daemon signs and stores a tamper-evident receipt for every tool call your agent makes. The signing keys and the receipt store live outside the agent process, so the audit trail holds up even if the agent is compromised.
- **Primary CTA:** Install the daemon
- **Secondary CTA:** Read the spec

## Why not X

**Why not Pipelock?**
Pipelock enforces policy at the egress and MCP boundary — it decides what the
agent is allowed to do. Agent Receipts records what happened, with keys held
outside the agent process. Different roles. Run both: Pipelock blocks, Agent
Receipts produces an independent audit trail.

**Why not Microsoft AGT?**
AGT is application middleware — policy, identity, and audit inside the agent
process. A compromised agent shares a trust boundary with its own audit log.
Agent Receipts moves signing and storage into a separate daemon, so the audit
trail survives agent compromise. Pair them when independent verifiability
matters.

**Why not a generic MCP firewall?**
MCP firewalls intercept tool calls and decide allow or deny — typically
in-process and scoped to the MCP channel. Agent Receipts records the decision
and outcome out-of-process, on a single chain spanning MCP, computer use, and
SDK channels. Complementary, not a substitute.

## What this is NOT

- **Not a policy engine.** Agent Receipts does not block, allow, rewrite, or rate-limit tool calls. Use a firewall (Pipelock, mcp-firewall) or governance framework (Microsoft AGT) for enforcement.
- **Not a competing standard.** Receipts use the same Ed25519 and SHA-256 primitives the rest of the space converged on, wrapped in the W3C Verifiable Credentials envelope. We are reusing standards, not authoring a new one.
- **Not a runtime sandbox.** Agent Receipts does not isolate the agent from the OS, network, or filesystem. Use a kernel-level tool (agentsh, sandbox-runtime) for that.

## Rationale

The agent security space crowded fast. By April 2026 there is at least one
mature implementation for every enforcement archetype — MCP proxy, egress
firewall, kernel sandbox, application middleware. Competing on enforcement
means picking a fight on someone else's turf, against teams with more resources
and earlier starts.

The recurring gap — called out in our own landscape analysis and in deployment
conversations — is verifiable audit: a record the agent itself cannot edit,
suppress, or fake. Microsoft AGT, Pipelock, and others sign receipts
in-process, which means a compromised agent can lie to its own audit log. The
daemon split (ADR-0010) and the W3C VC envelope (ADR-0003) are the two
structural choices that close that gap. Single-purpose, out-of-process,
standards-based. One thing done well, pairs cleanly with everything else in
the stack.
