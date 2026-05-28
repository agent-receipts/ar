# ADR-0025: Emit Failure Contract

## Status

Accepted

> Ratified under issue #599 (Closure 2). This document records the
> protocol-level *decision*; the per-SDK implementation, the conformance
> vector, and the documentation edits ship in the same pull request and are
> tracked as the checklist under *Consequences*.

## Context

Agent Receipts exists to produce a verifiable record of every agent action.
The single worst failure mode for a product in that class is an *undetectable*
hole in the chain: an action happened, no receipt was recorded, and nobody —
not the agent, not the operator, not an auditor — can tell.

Three of the SDK daemon-socket emitters do exactly this when the daemon is
unreachable:

The as-found state below is what this PR changes (locations given by symbol,
not line number, so they don't rot):

- **Python (PY-P9).** `DaemonEmitter.emit()` returned `None` in well under a
  millisecond when the socket could not be dialled, raised nothing, and logged
  at `DEBUG` only (`daemon_emitter.py`, in `emit` / `_dial_if_needed`).
- **Go (GO-P5).** `DaemonEmitter.Emit` returned `nil` on dial/write failure
  unless the caller opted into the old `WithStrictErrors()`
  (`sdk/go/emitter/emitter.go`). The default was silent, and
  `daemon-setup.mdx` *documented* the silent drop as expected behaviour.
- **TypeScript (suspected, then confirmed by reading).** `DaemonEmitter.emit`
  resolved to `null` on dial/write failure (`sdk/ts/src/daemon-emitter.ts`, in
  `emit` / `doWrite`). No strict mode existed.

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

### The issue's PY-P4 framing (revised by § 3 below)

Issue #599 framed PY-P4 as a *blocking prerequisite* for closing PY-P9: the
Python WAL-durability fix shipped in v0.10.0 wraps the HTTP delivery path but
cannot wrap `DaemonEmitter`, because the `Emitter` Protocol shape does not
capture the real arity of `DaemonEmitter.emit` (keyword-only `channel`,
`tool_name`, `decision`, ...). That framing assumed the fix for the silent drop
was to retrofit the WAL onto the daemon path — making PY-P4 a precondition.

The § 1 decision below dissolves that dependency (see § 3): the base obligation
is "surface the failure," and durability is a separate, opt-in concern. So
PY-P9 closes without PY-P4, and PY-P4 stays with ADR-0020 step-2 work. This
subsection is retained to record the original reasoning the decision revises.

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

### 3. PY-P4 is decoupled from PY-P9 by this decision

The issue framed PY-P4 (the `Emitter` Protocol does not capture
`DaemonEmitter.emit`'s arity, so a WAL emitter cannot wrap the daemon path) as a
*blocking prerequisite* for closing PY-P9. That framing assumed the fix for the
silent drop was to retrofit the WAL durability path onto `DaemonEmitter`.

This ADR's § 1 decision dissolves that dependency. The base obligation is
"surface the failure," and durability is a *separate, opt-in* concern. Closing
PY-P9 therefore needs only that `DaemonEmitter.emit` raise on transport failure
— it does **not** need the WAL to wrap the daemon path.

PY-P4 itself is a real but distinct item that stays with ADR-0020 step 2: the
`Emitter` Protocol and the WAL deal exclusively in signed `AgentReceipt`s, while
`DaemonEmitter` forwards *unsigned* tool-call frames and deliberately does not
implement the Protocol (ADR-0020 § "Migration"). Making the daemon path
WAL-wrappable requires the daemon to learn to ingest signed receipts (step 2),
not a redefinition of the Protocol to swallow the unsigned-frame arity — that
would fight ADR-0020's deliberate separation. PY-P4 is consequently **not** part
of this closure; it is tracked with step-2 durability work.

### 4. Where the contract is published

The binding requirement lives in **this ADR plus the conformance vector** (§5).
It is deliberately **not** added to `spec/v0.4.0/spec.md` now, for two reasons:

1. **Scope.** `spec.md` is the receipt *data model* — the W3C VC envelope,
   taxonomy, and chain verification. It does not touch a single receipt field;
   it constrains SDK *runtime* behaviour. Emitter/transport semantics have
   always lived in ADRs (0010, 0020), which is where an implementer already
   looks for them.
2. **Immutability cost.** Per ADR-0021 §D1, every released spec version from
   v0.4.0 onward is an immutable file: "editorial corrections to a released
   version are not made in place; they are made by releasing a new version with
   a CHANGELOG." v0.4.0 is released (2026-05-23, permanent URL). So *any* edit
   to `spec.md` — even a one-line non-normative note — forces cutting a new spec
   version. Driving a spec release purely to mention an SDK runtime obligation
   is the tail wagging the dog.

**Plan:** fold a normative line into the spec at the **next spec version cut**
that happens for a real data-model reason, rather than cutting a release for
this alone. Proposed wording to carry into that release:

> **Emit failure visibility.** The protocol's integrity guarantee assumes that
> the absence of a receipt is detectable. A conformant SDK emitter MUST surface
> transport failure to its caller rather than dropping events silently (see
> ADR-0025). Durability across process crashes is an opt-in concern (a WAL
> emitter) layered above this base obligation.

Consequence: the issue's "spec text documents the contract" acceptance box
stays unchecked until that next cut. The obligation is binding before then via
the ADR and the CI-gating conformance vector.

### 5. Conformance vector design

The existing cross-SDK vectors (`cross-sdk-tests/*.json`) are **data** vectors:
each SDK parses a JSON fixture and asserts a canonicalisation or verification
result. The emit failure contract cannot be expressed that way — it is a
**behavioural** contract about what an emit call returns when the transport is
absent. It needs a new kind of conformance artifact.

**Shape: a shared, machine-readable case list that every SDK test is required
to load and iterate.** This mirrors the existing cross-SDK convention (each SDK
loads the same `*_vectors.json`), but instead of asserting a canonicalisation
result, each SDK maps the emit outcome to a declared *outcome category*. The
case list — not three hand-written copies — is the single source of truth for
*which* cases exist, so a case cannot silently go unimplemented in one SDK.

- A new fixture `cross-sdk-tests/emit_failure_vectors.json` declares the
  scenarios and the required outcome category. Proposed shape:

  ```json
  {
    "version": 1,
    "description": "Emit failure contract (ADR-0025). Each SDK test MUST load this file, iterate every case, and fail on any case whose name it does not handle.",
    "outcome_categories": {
      "transport_error": "emit surfaced a transport failure (Go: non-nil error; Python: raised exception; TS: rejected Promise / returned Error)",
      "caller_error": "emit surfaced a caller-bug error, distinguishable from transport_error",
      "success": "emit reported success"
    },
    "cases": [
      {
        "name": "dial_failure_unreachable_socket",
        "setup": "Construct DaemonEmitter with a socket path that has no listener.",
        "action": "emit one well-formed event/receipt",
        "expect": "transport_error"
      },
      {
        "name": "caller_bug_invalid_decision",
        "setup": "Construct DaemonEmitter with a socket path that has no listener.",
        "action": "emit with an invalid decision value",
        "expect": "caller_error",
        "note": "Caller-bug errors MUST stay distinguishable from transport_error so callers can choose to retry only transport failures."
      }
    ]
  }
  ```

- **Enforcement (A′).** Each SDK's test loads `emit_failure_vectors.json`,
  iterates the `cases` array, runs each against its own `DaemonEmitter`, maps
  the native result to an outcome category, and asserts it equals `expect`. The
  iteration MUST fail loudly on any case `name` it does not recognise — that is
  what makes adding a case to the JSON break any SDK that has not implemented
  it, closing the drift gap of three independently maintained copies. The
  per-language *assertion* (what counts as a surfaced error) is necessarily
  native, since the contract is behavioural; the *case set and expected
  categories* are shared and data-driven.

- The Go cross-sdk-tests module can load the fixture directly. Python and TS
  load the same file from their own suites (path relative to the repo root, as
  the existing cross-language tests already do).

- "All three SDKs pass the vector" (issue acceptance) is satisfied when each
  SDK's data-driven test is green in its own CI lane. No polyglot live-daemon
  harness is introduced: "no daemon" simply means dialling a path with no
  listener, and the hard part — mapping that dial failure to the language's
  error channel — is irreducibly per-language, so a cross-process harness would
  share almost none of the real work while adding orchestration and flakiness.
  A live harness is held in reserve only if SDKs later diverge on error
  *taxonomy* in a way category-level coverage cannot catch.

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

These are the mechanical, farmable follow-ups the closure unblocks. Progress is
tracked here rather than as separate GitHub issues.

1. [ ] Carry the normative spec line (§ 4) into the next spec version cut — not
   a release on its own; requires explicit human approval to touch `spec/`.
2. [x] Add `cross-sdk-tests/emit_failure_vectors.json` (the shared case list)
   plus the data-driven Go conformance test that loads and iterates it (§ 5,
   A′).
3. [—] **PY-P4** (Protocol arity / WAL-wraps-daemon) — *not part of this
   closure*; decoupled by § 1 and moved to ADR-0020 step-2 durability work (§ 3).
4. [x] Python: raise `EmitTransportError` on transport failure in
   `DaemonEmitter.emit`, add `best_effort` opt-out; pass the vector.
5. [x] Go: flip the default so `Emit` returns a non-nil error on socket failure
   (`ErrTransport`-tagged), add `WithBestEffort` opt-out, retract the "drops
   silently" wording in `daemon-setup.mdx`.
6. [x] TypeScript: resolve with `EmitTransportError` on transport failure from
   `DaemonEmitter.emit`, add `bestEffort` opt-out; pass the vector.
7. [ ] Update the "Choosing an emitter" docs page (if it exists by then) to
   document the failure contract and the WAL wrapping pattern.

## Acceptance (from issue #599)

- [x] *(design)* Contract text documents the emit failure contract — § 1.
- [ ] *(spec)* Spec text documents the contract — deferred to the next spec
  version cut by § 4; binding via this ADR + the vector until then.
- [x] A conformance vector asserts emit-without-daemon surfaces error in each
  SDK — vector added (§ 5); Go, Python, and TypeScript lanes green.
- [x] All three SDKs pass the vector — Go, Python, and TypeScript done.
- [x] `daemon-setup.mdx` no longer documents silent drop as expected.
- [ ] "Choosing an emitter" page describes the WAL wrapping pattern — item 7.
