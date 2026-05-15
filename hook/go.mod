module github.com/agent-receipts/ar/hook

go 1.26.1

require github.com/agent-receipts/ar/sdk/go v0.8.0

require (
	// daemon is a test-only dep of sdk/go/emitter (integration build tag). Lazy loading
	// (go 1.17+) ensures it is never downloaded when building or installing this binary.
	github.com/agent-receipts/ar/daemon v0.8.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
)
