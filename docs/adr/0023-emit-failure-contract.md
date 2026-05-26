# ADR-0023: Emit Failure Contract

## Status

Proposed

> Draft for review under issue #599 (Closure 2). This ADR records the
> protocol-level decision only. The per-SDK implementation, the conformance
> vector, and the documentation edits are mechanical follow-through tracked as
> the spawned issues listed under *Consequences*, and are deliberately **not**
> part of this ADR's diff.

## Context

Agent Receipts exists to produce a verifiable record of every agent action.
The single worst failure mode for a product in that class is an *undetectable*
hole in the chain: an action happened, no receipt was recorded, and nobody —
not the agent, not the operator, not an auditor — can tell.

Three of the SDK daemon-socket emitters do exactly this when the daemon is
unreachable:

- **Python (PY-P9).** `DaemonEmitter.emit()` returns `None` in well under a
  millisecond when the socket cannot be dialled, raises nothing, and logs at
  `DEBUG` only (`sdk/py/src/agent_receipts/daemon_emitter.py:174`, dial failure
  path at `:316`).
- **Go (GO-P5).** `DaemonEmitter.Emit` returns `nil` on dial/write failure
  unless the caller opted into `WithStrictErrors()`
  (`sdk/go/emitter/emitter.go:174`, `:418`). The default is silent, and
  `site/src/content/docs/getting-started/daemon-setup.mdx` *documents* the
  silent drop as expected behaviour (lines 73, 81, 241, 252).
- **TypeScript (suspected, now confirmed by reading).** `DaemonEmitter.emit`
  resolves to `null` on dial/write failure
  (`sdk/ts/src/daemon-emitter.ts:290`, drop paths at `:406`). No strict mode
  exists.

The two audits scored identical behaviour differently — `med` for Python,
`high` for Go. The Go score is correct: silently producing an incomplete audit
trail is the highest-severity outcome for this product, and the
any-record-high-spans-2+-SDKs aggregation rule promotes it to P0.

### Why the current design says this is intentional

This is not an oversight; it is a documented design choice that this ADR now
revises.

- **ADR-0010 (daemon process separation)** states under *Failure model* that
  when the daemon is not running, "events truly drop silently. There is no
  daemon to record the gap, by definition." That reasoning is about the
  **in-chain** gap signal — the synthetic `events_dropped` receipt requires a
  live daemon to write it, so a missing daemon genuinely cannot leave an
  in-chain marker. The reasoning is sound *for the in-chain signal* and does
  **not** justify hiding the failure from the emitter's own caller.
- **ADR-0020 (emitter abstraction)** defines a `fire-and-forget` delivery
  *strategy* for `HttpEmitter` whose contract is explicitly "no delivery
  guarantee." That trades away *downstream acknowledgement*, not *local
  knowledge that dispatch failed*.

The conflation this ADR removes: "non-blocking" and "silent" have been treated
as the same property. They are not. An emitter can return within its
fire-and-forget latency budget **and** tell its caller that the transport was
unreachable. A failed `connect()` is known synchronously, in microseconds; it
costs nothing to report.

### Blocking prerequisite (PY-P4)

The Python WAL-durability fix shipped in v0.10.0 wraps the HTTP delivery path
but cannot wrap `DaemonEmitter` because the `Emitter` Protocol shape does not
capture the real arity of `DaemonEmitter.emit` (keyword-only `channel`,
`tool_name`, `decision`, ...). PY-P4 must be resolved as part of adopting this
contract, because a conformant "surface the failure, then opt into durability
by wrapping" story requires the wrapper to be able to wrap the daemon emitter
at all. Resolution order matters: PY-P4 before PY-P9.

## Decision

### 1. The emit failure contract (normative)

> A conformant Agent Receipts emitter MUST surface transport failure to its
> caller. When an emit operation cannot deliver an event or receipt to its
> transport — the daemon socket cannot be dialled, a write fails, a connection
> is reset, or a write deadline expires before the bytes are handed off — the
> emitter MUST report that failure through the language's normal error channel:
> a non-nil `error` return in Go, a raised exception in Python, a rejected
> Promise or returned `Error` in TypeScript. Silently returning a success/no-op
> value (`nil`, `None`, `null`, a resolved void Promise) on transport failure
> is non-conformant and is not a valid implementation choice.
>
> This requirement is independent of latency: emit MAY remain non-blocking and
> bounded (a dial timeout, a write deadline) and MAY decline to wait for
> downstream acknowledgement. What it MUST NOT do is convert a *known* transport
> failure into a silent success.
>
> Durability across process crashes is a separate concern and is **opt-in**,
> obtained by wrapping a base emitter in a write-ahead-log (WAL) emitter. The
> base emitter's obligation is narrower and unconditional: report the failure it
> already knows about.

#### What counts as a transport failure

| Situation | Knowable at emit time? | Contract |
|---|---|---|
| Dial fails (daemon down, socket missing, refused) | Yes, synchronously | MUST surface |
| Write fails / connection reset | Yes | MUST surface |
| Write deadline expires before handoff | Yes | MUST surface |
| Frame handed to kernel, daemon later crashes before persist | No | Out of scope — covered by `events_dropped` (live daemon) or WAL (durability) |
| Caller bug (empty channel, invalid decision, bad JSON, oversized frame, closed emitter) | Yes | Already surfaced today; unchanged |

The contract narrows precisely to the first three rows: failures the emitter
*observes* and currently *swallows*.

#### Interaction with `fire-and-forget` (ADR-0020)

`fire-and-forget` continues to mean "do not wait for the collector's 201/409
acknowledgement." It does **not** license swallowing a connection-refused or a
failed write. A `fire-and-forget` `HttpEmitter` that cannot open the connection
at all MUST still surface that. Per-event delivery acknowledgement remains
optional; *dispatch failure* does not.

#### Interaction with the drop counter / `events_dropped` (ADR-0010)

The drop counter and the synthetic `events_dropped` receipt are complementary,
not a substitute. They make a gap visible **in the chain** when a daemon is
alive to record it. The emit failure contract makes the gap visible **to the
caller** even when no daemon exists. Both stay. ADR-0010's statement that a
daemon-not-running drop leaves no *in-chain* marker remains true and unchanged;
this ADR adds that the same drop MUST still be visible to the caller.

### 2. Default vs. opt-in flips

Go's `WithStrictErrors()` is the correct *mechanism* but the wrong *default*.
Under this contract, surfacing transport failure becomes the default (and only
conformant) behaviour in all three SDKs. The opt-in moves to the other side:
callers who genuinely want best-effort, loss-tolerant emission opt into that
explicitly, and durability is obtained by opting into a WAL wrapper.

This is a **breaking behavioural change** for existing Go callers that rely on
the silent default and for all Python and TypeScript daemon-emitter callers. It
is intentional and is the entire point of the closure.

### 3. PY-P4 resolution

The Python `Emitter` Protocol is redefined so that it captures the real arity
of `DaemonEmitter.emit`, allowing a WAL emitter to wrap the daemon emitter. The
exact Protocol shape is Python-SDK implementation detail tracked in the spawned
Python issue; this ADR only requires that the shape be made wrappable as a
precondition for PY-P9.

### 4. Proposed normative spec text

The receipt-data-model spec (`spec/v0.4.0/spec.md`) describes receipts, not the
emitter transport layer, so the contract's normative home is this ADR plus the
conformance vector. If the maintainers want a pointer from the spec body, the
minimal addition is a single non-normative note in the design-principles area
referencing this ADR; the proposed wording is:

> **Emit failure visibility (non-normative).** The protocol's integrity
> guarantee assumes that the absence of a receipt is detectable. SDK emitters
> therefore MUST surface transport failure to their caller rather than dropping
> events silently; see ADR-0023. Durability across crashes is an opt-in
> (WAL) concern layered above this base obligation.

Whether this note lands in `spec/` is a maintainer call (spec changes require
explicit human approval); the binding requirement lives here and in the
conformance vector regardless.

### 5. Conformance vector design

The existing cross-SDK vectors (`cross-sdk-tests/*.json`) are **data** vectors:
each SDK parses a JSON fixture and asserts a canonicalisation or verification
result. The emit failure contract cannot be expressed that way — it is a
**behavioural** contract about what an emit call returns when the transport is
absent. It needs a new kind of conformance artifact.

**Shape: a shared behavioural test specification, implemented per SDK.**

- A new fixture `cross-sdk-tests/emit_failure_vectors.json` declares the
  scenarios and the required outcome, language-agnostically. Proposed shape:

  ```json
  {
    "version": 1,
    "description": "Emit failure contract (ADR-0023). Each SDK implements these as native tests against its own DaemonEmitter.",
    "cases": [
      {
        "name": "dial_failure_unreachable_socket",
        "setup": "Construct DaemonEmitter with a socket path that has no listener.",
        "action": "emit one well-formed event/receipt",
        "expect": "surface_transport_error",
        "must_not": "return success/None/null/nil"
      },
      {
        "name": "caller_bug_still_distinguishable",
        "setup": "Construct DaemonEmitter with a socket path that has no listener.",
        "action": "emit with an invalid decision value",
        "expect": "surface_caller_error",
        "note": "Caller-bug errors remain distinguishable from transport errors so callers can choose to retry only transport failures."
      }
    ]
  }
  ```

  (`emit_failure_vectors.json` is a *specification* the SDK tests read or mirror;
  it is not parsed into a receipt. The Go cross-sdk-tests module can load it
  directly; Python and TS mirror the same case list in their own test suites.)

- Each SDK adds a native test that, with no daemon listening on the configured
  socket, asserts emit surfaces a transport error (Go: non-nil `error`; Python:
  raised exception; TS: rejected Promise / returned `Error`). The test must also
  assert that a caller-bug input (e.g. invalid decision) surfaces a *distinct,
  distinguishable* error, so the two classes are not collapsed.

- "All three SDKs pass the vector" (issue acceptance) is satisfied when each
  SDK's native test is green in its own CI lane. No new cross-process harness is
  required; spinning up and tearing down a real daemon socket from a polyglot
  harness would add far more surface than the contract needs.

### 6. Records superseded / amended

- **ADR-0010** *Failure model*: the daemon-not-running bullet is amended to
  distinguish the (unchanged) absence of an in-chain marker from the (new)
  requirement to surface the failure to the caller. ADR-0010 is not superseded;
  it is clarified.
- **ADR-0020** `fire-and-forget` strategy: clarified to mean "no downstream
  acknowledgement wait," explicitly not "swallow dispatch failure."

## Consequences

### Easier

- The product's core promise — no undetectable gaps — holds at the SDK
  boundary, not just inside a running daemon.
- A uniform contract across three SDKs replaces three divergent, partly
  documented, partly accidental behaviours.
- The WAL durability story becomes composable: "I need durability across
  crashes" has one answer (wrap in a WAL emitter) that works because the base
  emitter reports failures the WAL can react to.

### More difficult / costs

- **Breaking change.** Existing Go callers depending on the silent default, and
  all Python/TS daemon-emitter callers, must handle a surfaced failure. This
  needs a clear changelog entry and a migration note per SDK.
- Callers that genuinely want best-effort emission must now opt in explicitly.

### Spawned follow-up work (not in this ADR's diff)

These are the mechanical, farmable issues the closure unblocks once this ADR is
ratified:

1. Spec note (if maintainers want it) per § 4 — requires explicit human
   approval to touch `spec/`.
2. Add `cross-sdk-tests/emit_failure_vectors.json` and the Go conformance test.
3. **Python: fix PY-P4** (Protocol arity) — prerequisite.
4. Python: raise on transport failure in `DaemonEmitter.emit`; pass the vector.
5. Go: flip the default so `Emit` returns a non-nil error on socket failure;
   retract the "drops silently" wording in `daemon-setup.mdx`.
6. TypeScript: surface transport failure from `DaemonEmitter.emit`; pass the
   vector.
7. Update the "Choosing an emitter" docs page (if it exists by then) to
   document the failure contract and the WAL wrapping pattern.

## Acceptance (from issue #599)

- [x] *(design)* Contract text documents the emit failure contract — § 1.
- [ ] A conformance vector asserts emit-without-daemon surfaces error in each
  SDK — design in § 5; implementation is spawned issue 2/4/6.
- [ ] All three SDKs pass the vector — spawned issues.
- [ ] `daemon-setup.mdx` no longer documents silent drop as expected — spawned
  issue 5.
- [ ] "Choosing an emitter" page describes the WAL wrapping pattern — spawned
  issue 7.
