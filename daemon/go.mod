module github.com/agent-receipts/ar/daemon

go 1.26.1

// Pin the toolchain to the patch (ADR-0031): reproducible-build attestation
// requires every builder use the same compiler bytes. CI consumes this via
// `setup-go` with go-version-file so it stops floating to the latest 1.26.x.
toolchain go1.26.1

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/agent-receipts/ar/sdk/go v0.20.0-alpha.1
	golang.org/x/sys v0.43.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.45.0 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.52.0 // indirect
)
