# Agent Receipts — Python SDK first-run audit

> **Re-audit delta — 2026-05-24 (post-weekend release).** Re-ran the full
> scenario after the weekend releases (sdk/py **v0.10.0**, daemon **v0.13.0**,
> mcp-proxy v0.12.0). The original report (below the delta) was against PyPI
> `0.9.0`; this delta records what changed. Evidence: `audit/test_first_run_e2e.py`
> now has **7 tests** (6 pass + 1 daemon round-trip that skips without a live
> daemon) and pins the regressions below.

## Re-audit delta

### Fixed / improved

- **#8 (silent data loss) — FIXED for the remote/HTTP path.** v0.10.0 ships a
  whole `agent_receipts.emitters` package: `HttpEmitter` (retrying HTTPS
  delivery), `CompositeEmitter`, `BufferingEmitter`, `InMemoryEmitter`, and
  crucially **`WalEmitter`** (`FileWal`/`MemoryWal`, `replay()`, `flush()`).
  Verified: a failed delivery now *raises and is retained* in the WAL
  (`pending()==1`) and `replay()` drains it (`delivered=1, remaining=0`) once the
  collector recovers — the opposite of 0.9.0's silent drop. Good fix.
- **macOS socket default moved off `$TMPDIR`** (#545) to
  `$XDG_DATA_HOME/agent-receipts/events.sock`, fixing the GUI-subprocess silent
  mismatch and bringing the macOS default inside the daemon's safe set.
- **New confirmation aids:** daemon v0.13.0 adds `agent-receipts show <seq>`
  (verified — prints receipt fields) and an `interrupted` terminal receipt on
  SIGTERM/SIGINT. Helps #7, though still CLI-only and not surfaced to Python users.
- **`Action.idempotency_key`** added (spec v0.4.0); `EmitterMetadata()` empty
  construction now raises (#509).

### Still open (unchanged by the release)

- **#1 root README `Receipt.create(...)` snippet — STILL BROKEN.** No `Receipt`
  class exists; README last touched in #496, not this weekend.
- **#2 / #3 PyPI README — STILL silent on the emitter story, now WORSE.** The
  README still documents only in-process create/sign and never mentions the
  emitter — and there is now an entire new `emitters` package it doesn't cover.
- **#4 stale `agent-receipts/sdk-py` CI badge — STILL present.**
- **#6 socket-guard vs docs contradiction — STILL present on Linux.** daemon #579
  keeps the Linux safe set at `$XDG_RUNTIME_DIR, /run, /var/run`; daemon-setup
  still recommends `~/.local/run/...` for non-root users, which that guard
  rejects. (macOS improved via #545.) I again needed `--unsafe-socket-path`.
- **#9 no CI recipe — STILL none** in the docs.
- **Local-path silent drop — STILL present.** `DaemonEmitter` (the renamed socket
  emitter) is unchanged fire-and-forget: daemon-down emit returns `None`, no
  retain, no signal. The WAL fix does **not** cover this path (see below).

### Newly broken / new paper-cuts

- **[HIGH] Breaking rename not flagged as breaking.** The socket emitter was
  renamed `Emitter` → **`DaemonEmitter`** (ADR-0020) and the top-level `Emitter`
  name now points to an un-instantiable **Protocol**. 0.9.0 code
  `Emitter(socket_path=...)` now dies with `TypeError: Protocols cannot be
  instantiated`. The sdk/py v0.10.0 CHANGELOG lists only the `PeerCredential`
  uid/gid change under *Breaking Changes* — this rename is buried under *Added*.
- **[HIGH] daemon-setup docs are now wrong against the shipped SDK.** The Python
  section still shows `from agent_receipts import Emitter; Emitter(socket_path=…)`
  (now broken) and still says *"Python SDK (v0.8.0a2) … `pip install --pre`"*. It
  should say `DaemonEmitter` and a current stable version.
- **[HIGH] PyPI publish lags the release.** sdk/py v0.10.0 is tagged/CHANGELOG'd
  in the repo (#588), but `pip install --upgrade agent-receipts` still serves
  **0.9.0**. A fresh adopter today gets the old build, with READMEs/docs that
  don't match either version. Confirm the `publish-py` workflow actually ran.
- **[MED] `runtime_checkable` Protocol false-positive footgun.** The new `Emitter`
  Protocol is `runtime_checkable`, so `isinstance(DaemonEmitter(), Emitter)` is
  `True` — but their `emit()` signatures differ (`emit(*, channel, tool_name,
  decision, …)` vs `emit(receipt)`). So `WalEmitter(inner=DaemonEmitter()).emit(r)`
  passes every type check and then crashes at runtime (`emit() takes 1 positional
  argument but 2 were given`). Net effect: **the local daemon socket path cannot
  be made durable via the WAL**, and the two abstractions silently mis-fit.
- **[MED] The headline v0.10.0 feature is undocumented.** No user-facing page
  shows `HttpEmitter`/`WalEmitter`/`CompositeEmitter` usage; how a Python app is
  now meant to deliver to a *local* daemon (socket) vs a *remote* collector
  (HTTP) is left for the reader to reverse-engineer from the package.

### Re-audit verdict

The WAL gap I flagged hardest (#8) is genuinely addressed for remote delivery —
good. But the release **regressed the first-run experience**: the one symbol an
adopter reaches for (`Emitter`) changed meaning, every emitter example in the
docs is now broken, and PyPI still serves the prior version. Net first-run is
*worse* than last week until the docs + PyPI publish catch up.

---

**Auditor stance:** senior Python dev, never seen this repo, time-boxed to ~30 min,
deciding whether to adopt.
**Environment:** fresh `python -m venv /tmp/ar-audit-venv`, Python 3.11.15, all
`AGENTRECEIPTS_*` env vars unset at start, Linux.
**Method:** user-facing docs only (PyPI/Python SDK README + docs-site pages).
Reading SDK/daemon source to answer a "how do I use this" question is itself
counted as a paper-cut.
**Verdict:** *Would adopt the in-process crypto API today; would NOT wire up the
daemon/collector path from the PyPI README alone* — the README never mentions it
exists.

---

## Scorecard

| Area | Result |
|---|---|
| `pip install agent-receipts` | Clean. Package name matches docs. Got `0.9.0`. |
| In-process hello-world (Python SDK README) | Copy-pastes and runs, zero env vars. |
| Root-README hello-world | **Broken** — imports a `Receipt` class that does not exist. |
| Dev-mode key story | No env var needed. No `AGENTRECEIPTS_PRODUCTION` gate exists in this SDK. |
| Collector/daemon story in README | **Absent.** Only on the docs site. |
| No-daemon failure mode | Silent drop, no exception, no SDK-side retention, no signal. |
| Documented CI pattern | None exists. |

---

## Part 1 — Install path

**What worked (the good news first):**

- `pip install agent-receipts` is exactly what the README says, resolves on
  PyPI, and installs `agent-receipts 0.9.0` with `pydantic` + `cryptography`.
  No package-name drift.
- The **Python SDK README's** Quick Start (`generate_key_pair` → `create_receipt`
  → `sign_receipt` → `hash_receipt` → `verify_receipt` → `verify_chain`)
  copy-pastes and runs **with zero environment setup**. Output:
  `Signature valid: True`, `Chain valid: True`.
- **Dev key story is frictionless.** `generate_key_pair()` works on a fresh box
  with no env vars. There is **no `GeneratingKeyProvider`, no dev/prod mode, and
  no `AGENTRECEIPTS_PRODUCTION` gate** anywhere in the Python SDK (the only
  `agentreceipts` string in the receipt models is the W3C `@context` URL). The
  "critical paper-cut" the brief worried about — a refuse-to-run dev key — **does
  not exist here.** Nothing to flag; this is a clean pass.

**Paper-cuts:**

1. **[HIGH] The root `README.md` Python snippet is broken.** It advertises:
   ```python
   from agent_receipts import Receipt
   receipt = Receipt.create(action="tool_call", payload=payload)
   signed = receipt.sign(private_key)
   ```
   `from agent_receipts import Receipt` → `ImportError: cannot import name
   'Receipt'`. There is no `Receipt` class. The real API is the functional one
   in the *Python SDK* README. The two READMEs disagree on the entire API shape,
   and the one a casual evaluator hits first (repo root) is the dead one.

2. **[MED] First-run collector story is invisible from the README.** The PyPI
   README documents only in-process create/sign/verify. It never mentions that
   an `Emitter`, a daemon, or a socket exist — yet `agent_receipts.Emitter`,
   `emitter`, `default_socket_path`, and `EmitterMetadata` are all exported at
   the top level. To find out what they do or how the "send a receipt to a
   collector" story works, I had to read `emitter.py` source. *Needing to read
   source to discover the headline feature is the paper-cut.*

3. **[MED] The README leads with a pattern the docs site calls deprecated.**
   `getting-started/quick-start.mdx` carries a prominent note: the in-process
   signing API is "the legacy in-process pattern that ADR-0010 deprecates in
   favour of the `agent-receipts-daemon`." The PyPI README presents that same
   in-process flow as *the* Quick Start with **no such note and no pointer to
   the daemon.** A reader who only sees PyPI adopts the deprecated path believing
   it's current.

4. **[LOW] CI badge points at the wrong repo.** The Python README's CI badge and
   several "Ecosystem" links target `github.com/agent-receipts/sdk-py`, but the
   code lives in the `agent-receipts/ar` monorepo. Looks like a leftover from a
   split-repo era; badge may be perpetually stale/404.

5. **[LOW] One README import reaches into a submodule.** `ActionInput` is
   imported from `agent_receipts.receipt.create`, not the top-level package,
   while everything around it is top-level. Minor inconsistency, easy to fumble.

**First-run collector story (no collector running):** see Part 2 — silent drop,
no error. From the README alone a reader wouldn't even know a collector is a
thing, so the "failure mode" is never surfaced to them at all.

---

## Part 2 — Local collector path

Terminology note up front: the brief says "collector"; the **product calls it the
`agent-receipts-daemon`**. (There is *also* a `collector/` directory in the repo
next to `daemon/`, which is its own source of confusion — but from user-facing
docs only the "daemon" exists.) I treated daemon == collector.

**Where the docs are / time to find:** Not in the Python README at all. Found via
the *root* README → "Daemon setup & migration guide" link →
`agentreceipts.ai/getting-started/daemon-setup/`
(`site/.../getting-started/daemon-setup.mdx`). ~3–4 min, and only because the
*root* README linked it — the *Python SDK* README never does.

**Homebrew:** Docs say `brew install agent-receipts/tap/agent-receipts-daemon`.
`brew` is not installed in this environment, so I could not run
`brew search agent-receipts` to confirm the tap is real and current.
**[LOW, can't-verify]** A macOS dev without the tap is steered to `go install`,
which requires **Go 1.26.1+** — bleeding-edge; many devs won't have it. There is
no prebuilt non-Homebrew binary mentioned for someone who has neither brew nor a
current Go.

**Build/install — timed:** Built from in-tree source (Go workspace):
```
go build -o /tmp/ar-daemon  ./daemon/cmd/agent-receipts-daemon
go build -o /tmp/ar-verify  ./daemon/cmd/agent-receipts
```
~31 s including first-time dependency download. Smooth, no errors. (The repo also
ships a root `./agent-receipts` binary, but it's a non-Linux build —
`Exec format error` — so useless on this box.)

**Init + start:** `agent-receipts-daemon --init` generated the key pair cleanly.
Starting the daemon:

6. **[HIGH] The documented non-root socket workaround is rejected by the daemon's
   own guard.** First `--init`'d daemon start with `AGENTRECEIPTS_SOCKET` under
   `/tmp` refused to boot:
   > socket path "…/events.sock" is outside the per-platform safe set
   > `[/run, /var/run]`; refusing to start … pass `--unsafe-socket-path` to
   > override (issue #538)

   But the **daemon-setup docs explicitly tell non-root users**:
   > "set `AGENTRECEIPTS_SOCKET` to a user-writable path (for example
   > `~/.local/run/agentreceipts/events.sock`)"

   `~/.local/run/...` is **also** outside `[/run, /var/run]`, so following the
   documented advice verbatim hits the same refusal. The docs' recommended escape
   hatch contradicts the binary's enforcement. A non-root Linux dev without
   `$XDG_RUNTIME_DIR` is stuck unless they discover `--unsafe-socket-path`
   themselves. (I used `--unsafe-socket-path` to proceed.)

**Listening confirmation — good:** startup log is clear and sufficient:
```
… published public key to …/signing.key.pub
… loaded chain default, next seq=1
… agent-receipts-daemon listening on …/events.sock (chain=default, db=…/receipts.db)
```

**Round-trip — works:** Python `Emitter(...).emit(channel=…, tool_name=…,
decision="allowed", input=…, output=…)` → daemon → DB. Confirmed via the CLI:
```
$ AGENTRECEIPTS_DB=…/receipts.db agent-receipts verify --public-key …/signing.key.pub
Chain default: VALID (1 receipts)
```

7. **[MED] Confirmation path is not obvious from the Python user's docs.** The
   confirming command (`agent-receipts verify`) lives on the daemon-setup page,
   not in the Python README. A Python dev who emitted a receipt has no in-SDK way
   to confirm it landed — `emit()` returns `None` either way (see below) — and
   nothing in the package they installed points them to the verify CLI.

**Now break it (stop daemon, emit again):**

- `emit()` returned `None` in **0.2 ms**, raised nothing. (Fast because the stale
  socket file lingers and gives immediate `ECONNREFUSED`; against a missing file
  it would burn the 25 ms dial timeout, per the docs.)
- **No SDK-side WAL, no buffer, no pending file.** Only `receipts.db`,
  `signing.key*`, and the daemon log exist; the dropped event left no trace.
- Chain length stayed at 1 — the dropped receipt simply never existed.
- **Zero user-visible signal.** The drop is logged at `DEBUG` on the SDK logger
  and nowhere else. With default logging, a dev sees absolutely nothing.

8. **[HIGH] Silent data loss with no signal.** This is by design ("fire-and-forget",
   per `emitter.py` docstring and the daemon-setup "events are dropped silently"
   line), and it's a defensible default for a hot path. But for a first-run dev it
   is a trap: start coding before the daemon is up, emit 1,000 receipts, and your
   audit trail is *empty* with no error, no warning, no count, no pending queue.
   The only documented detection is "check `pgrep agent-receipts-daemon` and that
   the socket exists" *after* you notice receipts are missing. There is no
   `emit()`-level health signal, no startup "daemon unreachable" warning, and no
   optional buffering. For a *tamper-evidence/audit* product, silent omission is
   the most dangerous failure class.

---

## Part 3 — CI shape

**Is there a documented CI pattern?** **No.** Grepping the docs site and SDK
README for `CI` / `GitHub Actions` / `continuous integration` turns up only blog
and ecosystem-landscape prose — nothing showing a user how to run Agent Receipts
in their own pipeline. No `services:` daemon-as-a-service example anywhere.

9. **[MED] No CI story for adopters.** Given the daemon is now mandatory for the
   recommended (non-deprecated) path, the absence of a "run the daemon in CI"
   recipe is a real gap — every adopter has to invent the orchestration (start
   daemon → wait for socket → run app → verify chain → tear down) themselves,
   including rediscovering the `/tmp` safe-set refusal from Part 2.

**Drafted `.github/workflows/agent.yml`** (what the docs *should* ship). Not
committed to `.github/` per repo agent-safety rules; provided as the audit
deliverable `audit/agent-ci-example.yml`. Shape:

- `go install …/agent-receipts-daemon@<pinned>` and `…/agent-receipts@<pinned>`.
- `agent-receipts-daemon --init`.
- Start daemon in background on a **CI-safe socket** — on a GitHub runner
  `$XDG_RUNTIME_DIR` is usually unset, so this needs `/run/agentreceipts/...`
  (root) or `--unsafe-socket-path` (paper-cut #6 bites here too).
- Poll for the socket / "listening" log before running the app.
- `pip install agent-receipts`, run the app, then
  `agent-receipts verify --public-key …` and assert `VALID`.

---

## Fix-tonight (things I was tempted to fix but didn't)

- **#1** Delete or correct the root README's `Receipt`-class Python snippet so it
  matches the real functional API (or ship a `Receipt` facade).
- **#3 / #2** Add a banner to the PyPI/Python README: "in-process signing is the
  standalone/testing path; for production use the daemon — see Daemon Setup," and
  link the daemon docs + document `Emitter` in the README.
- **#6** Reconcile the safe-set guard with the docs: either add
  `~/.local/run`/`$HOME`-rooted paths to the allowed set, or stop recommending
  `~/.local/run/...` and tell non-root users to use `--unsafe-socket-path`
  (or set `$XDG_RUNTIME_DIR`).
- **#8** Add an opt-in startup/first-emit "daemon unreachable" warning (one line,
  once), or a `dropped_count`, so silent loss is detectable without DEBUG logs.
- **#7** Mention `agent-receipts verify` in the Python README so emitter users
  can confirm receipts landed.
- **#4** Fix the `sdk-py` badge/links to point at the `agent-receipts/ar` monorepo.
- **#9** Ship the CI recipe (see `audit/agent-ci-example.yml`).

## Follow-ups / uncertainties

- Could not verify the Homebrew tap exists (`brew` absent here) — confirm
  `agent-receipts/tap/agent-receipts-daemon` resolves on a real Mac.
- Version coherence: PyPI stable is `0.9.0`, but daemon-setup pins the daemon to
  `@v0.8.0` and tells Python users `pip install --pre …@0.8.0a2`. Which
  daemon/SDK versions are actually a supported, tested pair is unclear from the
  docs.
- The repo has both `daemon/` and `collector/` top-level dirs; from user docs
  only "daemon" is referenced. Worth clarifying which is canonical.

## What I verified (reproducible)

- `audit/test_first_run_e2e.py` — 4 passing tests against the installed `0.9.0`
  package: in-process happy path, 2-link chain + tamper detection, emitter
  round-trip vs. a live daemon, and the no-daemon silent-drop contract.
  `test_emitter_roundtrip_against_live_daemon` skips unless
  `AGENTRECEIPTS_SOCKET` points at a running daemon.
