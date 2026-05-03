# ADR-0016: Audit Store Encryption at Rest (mcp-proxy)

## Status

Proposed

## Context

The mcp-proxy SQLite audit store records the JSON-RPC request and response traffic between MCP clients and MCP servers. After redaction (see [ADR-0012](./0012-payload-disclosure-policy.md)), a redacted view of the raw envelope, the tool-call arguments, the response result, and any error are persisted alongside each receipt. Even post-redaction, these fields routinely contain commercially or operationally sensitive content: filenames, branch names, ticket bodies, partial code, search queries, customer-facing strings. Redaction removes credentials and known-sensitive patterns; it is not a substitute for confidentiality of the remainder.

The original threat model assumed the SQLite file lived on the operator's local disk under their primary user account, in which case file-system permissions were sufficient. That assumption no longer holds. Operators ship audit databases off the host: backup to S3, archival to cold storage, replication into a SIEM, mount over network filesystems for centralised review. Once the file moves off the originating machine, every reader of the destination becomes a reader of the audit content, and the local-disk assumption stops paying for itself.

This ADR documents the encryption design that already ships in `mcp-proxy/internal/audit/encrypt.go`. It exists because the implementation evolved through three iterations under a changing threat model, the rationale was scattered across commit messages and a code-scanning finding, and the current state needs to be readable as a deliberate design rather than an accreted one. Three questions had to be answered:

1. **Cipher**: how should an individual field be protected at rest?
2. **Key derivation**: the input is an operator-supplied passphrase rather than a high-entropy key, so a KDF is required — which one, and tuned how?
3. **Salt strategy**: hardcoded, passphrase-derived, per-row, or per-installation?

A previous iteration used a constant compile-time salt. That choice was caught during code-scanning review once remote storage entered the picture: with a constant salt, the same passphrase produces the same key across every installation, so an attacker who obtains one passphrase or precomputes a dictionary against the constant salt can attack every other install for free. The salt question is the one that turned the design from "passable for local files" into "needs to hold up under remote storage."

Encryption is configured per-installation by setting `BEACON_ENCRYPTION_KEY` in the proxy's environment. When the variable is empty, encryption is disabled and audit fields are written in cleartext (post-redaction). Receipt signing (Ed25519, [ADR-0001](./0001-ed25519-for-receipt-signing.md)) and chain integrity ([ADR-0008](./0008-response-hashing-and-chain-completeness.md)) are independent of this layer and unaffected.

Related: #61.

## Decision

Encrypt redacted audit fields at rest with **AES-256-GCM**. Derive the encryption key from the operator-supplied passphrase using **Argon2id** with parameters `time=1, memory=64 MiB, parallelism=4, output=32 bytes`. Bind the derivation to a **per-installation random 16-byte salt**, generated on first use and persisted in the SQLite `metadata` table.

### Cipher — AES-256-GCM

- **AEAD construction.** GCM provides confidentiality and integrity in one primitive; an attacker who flips ciphertext bits cannot produce a value that decrypts cleanly. This matters because audit fields are read back by tooling (`mcp-proxy inspect`, `mcp-proxy export`) which would otherwise trust whatever came back from the database.
- **Standard, well-reviewed, and available in the Go standard library** (`crypto/aes`, `crypto/cipher`). Avoiding third-party crypto reduces supply-chain risk for a security-relevant code path.
- **96-bit random nonce per encryption** (`crypto/rand`). Each call generates a fresh nonce, so the same plaintext encrypts to different ciphertexts on each write. The nonce is stored as a prefix on the ciphertext.
- **Wire format.** Encrypted fields are stored as `enc:` + base64(nonce ‖ ciphertext ‖ tag). The `enc:` prefix discriminates encrypted from cleartext values, so decryption code only attempts to decrypt values that were actually encrypted, and tooling can identify encrypted fields without trial decryption.

### KDF — Argon2id (1, 64 MiB, 4, 32)

- **Argon2id over PBKDF2 / scrypt / bcrypt.** Argon2 is the [Password Hashing Competition](https://www.password-hashing.net/) winner and the OWASP-recommended default for password-based key derivation. The `id` variant blends Argon2i's side-channel resistance with Argon2d's GPU resistance.
- **Parameters at the OWASP baseline.** `time=1, memory=64 MiB, parallelism=4` is OWASP's [first recommended Argon2id profile](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id). Memory cost dominates — 64 MiB per derivation makes commodity-GPU dictionary attacks expensive and ASIC attacks unattractive at scale.
- **Derivation runs once per process.** Cost is paid at proxy startup, not on the encrypt/decrypt path. Per-row cryptographic cost is therefore a single GCM seal/open, not a KDF call. This means the parameters can be tuned for the attacker's offline cost without paying that cost at request time.
- **32-byte output** matches the AES-256 key size, so no truncation or expansion is needed.

### Salt — per-installation, random, persisted

- **16 random bytes** generated by `crypto/rand` on first encryption setup. The bytes are hex-encoded and stored in the SQLite `metadata` table under the key `encryption_salt`.
- **Per installation, not per row.** The same key is reused across rows of one installation; reuse is safe because every encryption uses a fresh GCM nonce. Per-row salts would force a per-row Argon2id derivation, which is incompatible with the 64 MiB cost above.
- **Generated lazily, persisted atomically.** `Store.EncryptionSalt()` uses `INSERT OR IGNORE` plus a re-read so concurrent first-run callers converge on the same salt rather than racing to install different ones. A read-only variant (`EncryptionSaltIfPresent`) exists for scanners that must not mutate the audit store.
- **No constant or passphrase-derived salt.** A constant salt makes the same passphrase produce the same key across installations, which permits offline precomputation against any one installation to apply to all. A passphrase-derived salt has the same defect by construction: the salt is no longer independent of the secret it is supposed to harden, and rainbow-tables remain reusable across installations that happen to choose the same passphrase.

### Passphrase ingestion

- The passphrase is read from the `BEACON_ENCRYPTION_KEY` environment variable.
- Empty value → `NewEncryptor` returns `nil` and the proxy writes cleartext audit fields. This is an explicit "encryption disabled" mode, not an error.
- Non-empty value with no salt yet recorded in the database → salt is generated on first encryption and pinned for the life of the database.
- Non-empty value when a salt exists in the database → the salt is loaded and the key is re-derived; if the passphrase has changed, decryption of existing rows will fail loudly (GCM authentication tag mismatch).

### Fail-closed, not fail-open

When encryption is enabled, every encrypt path returns an error on failure rather than silently storing plaintext. The audit pipeline propagates that error rather than degrading. An audit store that quietly downgrades to cleartext on a transient crypto error is worse than one that refuses to write — silent downgrade is exactly the failure mode that the encryption layer is supposed to prevent.

## Security Considerations

### What is encrypted, and what is not

Encryption applies field-by-field to the redacted JSON envelope, the redacted arguments string, the redacted result, and any redacted error string. The following are **not** encrypted and remain readable from the SQLite file alone:

- Receipt UUIDs, sequence numbers, prev-hash links, signatures, and public-key material — the chain is signature-protected, not encryption-protected, and must remain verifiable without the passphrase ([ADR-0001](./0001-ed25519-for-receipt-signing.md), [ADR-0008](./0008-response-hashing-and-chain-completeness.md)).
- Receive timestamps and other receipt-envelope metadata.
- Tool name, MCP server name, decision (`allowed`/`denied`/`pending`), risk score, classifier output.
- Intent-tracking data (intent ids, ordering).

Operators who consider tool name or timing itself sensitive need a different control: at the protocol level, this layer encrypts content, not metadata. The current design is deliberate — verifiers and reporting tooling need timestamps, decisions, and tool names to function without holding the encryption passphrase.

### Cross-installation precomputation

The per-installation random salt is the load-bearing defence here. Two installations running the same passphrase derive different keys, so an attacker who breaks one installation's passphrase (by stealing the env var, brute-forcing a weak choice, or precomputing against the leaked salt) gains nothing against any other installation. The constant-salt iteration of this code did not have that property and was the trigger for the current design.

### Argon2id parameters and the upgrade path

`time=1, memory=64 MiB, parallelism=4` is the OWASP minimum, not a ceiling. The right way to read these numbers is "the lowest defensible setting today"; they should rise as commodity hardware rises. Because the parameters are constants in source rather than encoded into stored ciphertext, raising them is a code change today, not a parameter-rotation flow. Any future change must coordinate with the rotation work in [ADR-0015](./0015-key-rotation-byok-anchoring.md) — encryption-key rotation is not yet covered (see Known Limitations) but the eventual mechanism should carry the Argon2 parameters forward in band so historical rows remain decryptable after a parameter bump.

### Authenticated additional data (AAD)

The current `cipher.AEAD.Seal` and `Open` calls pass `nil` for AAD. This means a ciphertext encrypted in one column or row is cryptographically valid in any other column or row of the same database — moving an `enc:` value to a different field would still decrypt cleanly. In practice this is bounded by the surrounding SQL schema (each ciphertext is associated with a specific receipt row, and rows are signature-protected via the receipt envelope), but a future revision may bind ciphertexts to their (receipt UUID, field name) by passing it as AAD. Adding AAD later is a one-way compatibility break for stored ciphertexts unless rotation is in place; it is therefore listed as future work rather than an immediate fix.

### Length and timing side-channels

GCM ciphertext length equals plaintext length plus a fixed 12-byte nonce and 16-byte tag. The encrypted size of an audit field therefore reveals the plaintext size to within ±0 bytes. For audit content this is acceptable: the volume of MCP traffic and field structure is already observable from row counts and timestamps. Padding to bucket sizes was considered and rejected as adding cost without changing the actual exposure.

Timing side-channels in AES-GCM are a property of the underlying implementation. Go's `crypto/aes` uses constant-time AES on amd64/arm64 platforms with hardware AES support, which covers the proxy's supported targets.

### Failure modes that look like attack

- **Wrong passphrase, right salt.** GCM `Open` returns an error; tools surface "decryption failed" and the row is treated as undecryptable. This is indistinguishable from intentional tampering by design — the operator, not the proxy, is the one who knows whether a passphrase was rotated.
- **Right passphrase, wrong salt** (e.g. salt was reset or the database was swapped underneath the running proxy). Same observable behaviour. The `mcp-proxy audit-secrets` flow exists to diagnose this case explicitly rather than relying on operator inference.
- **Encrypted DB without the passphrase.** The proxy refuses to read encrypted columns; `audit-secrets` reports `encrypted-no-key`. This is documented operator-visible behaviour, not a bug.

## Known Limitations

These are the assumptions and gaps inherent in the current design. They are listed deliberately so that future ADRs (especially around rotation, BYOK, and daemon ownership) can address them with the original constraints visible.

- **Single passphrase, no key rotation.** Changing `BEACON_ENCRYPTION_KEY` without re-encrypting existing rows leaves those rows undecryptable. There is no in-place rewrite tool today. Rotation will eventually be covered by the broader key-rotation work in [ADR-0015](./0015-key-rotation-byok-anchoring.md), which is currently scoped to signing keys; an encryption analogue is out of scope here.
- **Passphrase lives in environment.** `BEACON_ENCRYPTION_KEY` is read from the process environment. This is operationally simple — secrets managers, systemd `EnvironmentFile`, launchd plists, and CI runners all surface env vars natively — but it puts the passphrase in `/proc/<pid>/environ`, in process listings under some configurations, and in any crash dump that includes the environment. A keychain/HSM-backed `KeySource` analogous to the signing-side abstraction in [ADR-0015](./0015-key-rotation-byok-anchoring.md) is the right long-term landing place; it is not in scope for this ADR.
- **Metadata is not encrypted.** Tool names, timestamps, decisions, and intent ids are queryable cleartext. This is deliberate (verifiers need them) but operators who treat metadata itself as sensitive must add a layer on top.
- **AAD is not bound.** Ciphertexts are not cryptographically bound to their containing row or column (see Security Considerations).
- **No passphrase strength enforcement.** The proxy treats `BEACON_ENCRYPTION_KEY` as a high-entropy operator-managed secret. A weak passphrase weakens the entire scheme; Argon2id raises the cost of a dictionary attack but does not make a four-character passphrase safe. This is documented; it is not enforced in code.
- **Per-installation, not per-tenant.** A single mcp-proxy installation has a single encryption key. Multi-tenant deployments that need separation of audit confidentiality per tenant must run separate proxy instances.
- **Salt rotation = full re-encryption.** Rotating the salt is equivalent to rotating the key: every encrypted row would have to be re-encrypted under the new derivation. Same constraint as passphrase rotation, same future work.

## Consequences

### Positive

- A stolen audit database file — backup, snapshot, replicated copy, lost laptop — does not by itself expose redacted payload content. The attacker additionally needs `BEACON_ENCRYPTION_KEY`.
- The "remote storage" threat model that triggered the redesign is now explicitly accounted for: per-installation salts mean cross-install precomputation does not amortise.
- Receipt verifiability is unchanged. A verifier with the public key but not the passphrase can still confirm chain integrity over the receipts; only the encrypted content fields are opaque to them.
- The cipher and KDF choices are off-the-shelf primitives in the Go standard library / `golang.org/x/crypto`. No bespoke crypto, no third-party crypto SDK in a security-critical path.
- The design is documented and provisional aspects (rotation, BYOK, AAD binding) are flagged rather than implicit. Future revisions inherit a stated baseline.

### Negative / tradeoffs

- Operational complexity: operators must store and protect `BEACON_ENCRYPTION_KEY` themselves. The proxy gives no guidance on where (vault, secret manager, CI variable, ops-runbook envelope), which is correct — that is operator policy — but it is a real adoption cost compared to "no encryption."
- Loss of the passphrase = loss of decryptability for affected rows. There is no recovery path. This is the desired property of an encryption layer, but worth stating bluntly.
- Argon2id at 64 MiB raises proxy startup memory by that amount briefly. Negligible on workstations and servers; potentially relevant in heavily containerised deployments with tight memory limits.
- Adds a config surface (`BEACON_ENCRYPTION_KEY`, salt persistence, `audit-secrets` diagnostics) that has to be tested and kept consistent across `serve`, `inspect`, `verify`, `export`, and any future reader.

## Related ADRs

- [ADR-0001 (Ed25519 for receipt signing)](./0001-ed25519-for-receipt-signing.md) — receipt signatures are independent of this layer; chain verification does not require the encryption passphrase.
- [ADR-0004 (SQLite for local receipt storage)](./0004-sqlite-for-local-receipt-storage.md) — both the encrypted ciphertexts and the encryption salt live in the same SQLite file.
- [ADR-0008 (Response hashing and chain completeness)](./0008-response-hashing-and-chain-completeness.md) — chain integrity is signature-protected and remains intact whether or not encryption is enabled.
- [ADR-0010 (Daemon process separation)](./0010-daemon-process-separation.md) — once signing moves into the daemon, the passphrase model is a natural candidate to move with it; the daemon becomes the sole holder of both the signing key and the encryption-passphrase-derived key.
- [ADR-0012 (Payload disclosure policy)](./0012-payload-disclosure-policy.md) — redaction runs before encryption. The two layers are complementary: redaction removes known-sensitive substrings, encryption protects the remainder.
- [ADR-0015 (Key rotation, BYOK, external anchoring)](./0015-key-rotation-byok-anchoring.md) — covers signing keys. The encryption analogue (passphrase rotation, BYOK for the encryption key, parameter-bump migration) is future work that should reuse the same `KeySource` shape rather than inventing a parallel one.
