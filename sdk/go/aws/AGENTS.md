# AGENTS.md

AWS adapter for the Go SDK. Implements the ADR-0018 `Signer` abstraction backed
by AWS KMS (`KMSSigner`), so an Ed25519 private key can sign receipts without
ever leaving KMS. Separate Go module: the core `sdk/go` package stays free of
AWS dependencies.

## Getting started

```sh
go build ./...   # build
go vet ./...     # static analysis
gofmt -l .       # formatting (must print nothing)
go test ./...    # unit tests — mocked KMS client, no network or credentials
```

## Project structure

```
kms.go               # KMSSigner: NewKMSSigner, Sign, GetPublicKey, options
kms_test.go          # unit tests against a mocked KMSClient
integration_test.go  # real-KMS test, skipped unless AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN is set
```

## Conventions

- All changes go through pull requests — never push directly to main.
- This module must not modify core `sdk/go`; it only depends on `aws-sdk-go-v2`.
- Use `aws-sdk-go-v2` (never v1).
- KMS signing uses `SigningAlgorithm=ED25519_SHA_512` + `MessageType=RAW`
  (pure Ed25519, RFC 8032). Do not switch to `ED25519_PH_SHA_512`.
- Surface AWS SDK errors verbatim — callers distinguish throttling, access
  denied, and key-not-found.
- Do not add a retry layer; `aws-sdk-go-v2` already retries.
- Tests must not require live AWS — gate integration tests behind the env var.

## Reference files

- `kms.go` — the `KMSClient` interface is the seam for mocking; keep it minimal.
- `kms_test.go` — `mockKMS` is backed by an in-test Ed25519 key so signatures
  produced by `Sign` verify against `GetPublicKey`.
