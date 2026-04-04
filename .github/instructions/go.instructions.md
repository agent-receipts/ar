---
applyTo:
  - "sdk/go/**"
  - "mcp-proxy/**"
---

# Go review guidelines

- Pure Go SQLite via modernc.org/sqlite — flag any CGO dependencies.
- Errors must be wrapped with context (`fmt.Errorf("operation: %w", err)`). Flag bare error returns.
- Tests sit alongside source files as `*_test.go`. Flag test files in separate directories.
- Run `go vet ./...` before committing.
- The mcp-proxy depends on sdk/go via a `replace` directive — changes to sdk/go should trigger mcp-proxy test verification.
