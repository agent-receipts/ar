module github.com/agent-receipts/ar/daemon

go 1.26.1

// The pinned sdk/go version (v0.6.0) is the latest published tag at the time
// this module landed. Phase 1 also introduced ReceiptStore.GetChainTail in
// sdk/go, which is NOT in v0.6.0 — so standalone `go install` of this daemon
// is not yet possible. The repo-root go.work resolves the in-tree sdk/go for
// monorepo builds and CI. The follow-up release of sdk/go (the next semver
// tag from .github/workflows/publish-go.yml) ships the new symbol, and a
// small follow-up PR will bump this require accordingly — at which point the
// `replace` below MUST be removed (this daemon module's first publish step
// will be gated on the absence of local replace directives, mirroring the
// sdk/go publish workflow).
//
// Tracked with the rest of Phase 2 sequencing in
// https://github.com/agent-receipts/ar/issues/236.
require (
	github.com/agent-receipts/ar/sdk/go v0.6.0
	golang.org/x/sys v0.43.0
)

// Local replace closes the GOWORK=off gap: in-repo developers and CI matrices
// that disable the workspace (e.g. to verify each module's go.mod independently)
// resolve sdk/go from the in-tree path that contains GetChainTail. Has no
// effect for `go install` from a clone of an external project (those callers
// see only the proxy-published require above, which is the documented
// limitation in README.md until sdk/go's next semver tag publishes
// GetChainTail).
//
// REMOVE BEFORE PUBLISHING THIS MODULE — see the comment block above.
replace github.com/agent-receipts/ar/sdk/go => ../sdk/go

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.72.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.50.0 // indirect
)
