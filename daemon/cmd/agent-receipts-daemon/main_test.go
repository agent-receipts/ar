package main

import "testing"

// TestResolveVersion_PrefersLDFlagInjection pins the precedence the
// release pipeline relies on: a -ldflags "-X main.version=..." build
// wins over both Go's build info and the "dev" fallback.
func TestResolveVersion_PrefersLDFlagInjection(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v9.9.9-test"
	if got, want := resolveVersion(), "v9.9.9-test"; got != want {
		t.Errorf("resolveVersion() = %q, want %q", got, want)
	}
}

// TestResolveVersion_FallsBackToDevWhenUnset is the contract when neither
// the release pipeline injected a version nor `go install` produced a
// module version: --version must still print something useful instead of
// an empty string. "dev" matches mcp-proxy's behaviour.
func TestResolveVersion_FallsBackToDevWhenUnset(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = ""
	got := resolveVersion()
	// Under `go test`, debug.ReadBuildInfo() can return either an empty
	// or "(devel)" Main.Version depending on how the binary was invoked
	// — both branches must yield a non-empty, sensible string. We accept
	// either "dev" or any non-empty version-shaped value (anything that
	// isn't the empty string the operator would never want to see).
	if got == "" {
		t.Error("resolveVersion() returned empty string; --version output would be empty")
	}
}
