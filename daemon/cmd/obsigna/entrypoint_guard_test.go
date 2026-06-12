package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// goreleaserBuild is one entry under the goreleaser `builds:` list.
type goreleaserBuild struct {
	id, main, binary string
}

// parseGoreleaserBuilds extracts (id, main, binary) for each build by scanning
// the YAML lines. A tiny hand parser avoids pulling a YAML dependency into the
// daemon module just for a guard test. A new build begins at each `  - ` list
// marker inside the `builds:` section; id/main/binary are captured in ANY order
// within a build (the first may sit on the dash line), so reformatting that
// reorders fields cannot silently misassign them.
func parseGoreleaserBuilds(t *testing.T, yaml string) []goreleaserBuild {
	t.Helper()
	topKey := regexp.MustCompile(`^[a-z]`)
	// "  - key: value" — a build list item with its first key on the dash line.
	itemRe := regexp.MustCompile(`^  - (\w[\w-]*):\s*(\S+)`)
	// "    key: value" — any subsequent key inside the current build.
	keyRe := regexp.MustCompile(`^\s+(\w[\w-]*):\s*(\S+)`)

	set := func(b *goreleaserBuild, key, val string) {
		switch key {
		case "id":
			b.id = val
		case "main":
			b.main = val
		case "binary":
			b.binary = val
		}
	}

	inBuilds := false
	var builds []goreleaserBuild
	for _, line := range strings.Split(yaml, "\n") {
		// Any column-0 key ends the builds: section.
		if topKey.MatchString(line) {
			inBuilds = strings.HasPrefix(line, "builds:")
			continue
		}
		if !inBuilds {
			continue
		}
		if m := itemRe.FindStringSubmatch(line); m != nil {
			builds = append(builds, goreleaserBuild{})
			set(&builds[len(builds)-1], m[1], m[2])
			continue
		}
		if len(builds) == 0 {
			continue
		}
		if m := keyRe.FindStringSubmatch(line); m != nil {
			set(&builds[len(builds)-1], m[1], m[2])
		}
	}
	return builds
}

// TestObsignaIsPrimaryEntrypoint is the anti-regression gate: the primary receipt
// CLI must build from ./cmd/obsigna as the `obsigna` binary, and `agent-receipts`
// may appear ONLY as the deprecation shim. If someone reintroduces agent-receipts
// as a primary entrypoint (e.g. points the obsigna source at an agent-receipts
// binary, or gives the shim the real command surface) this fails.
func TestObsignaIsPrimaryEntrypoint(t *testing.T) {
	yaml := readFile(t, "../../.goreleaser.yaml")
	builds := parseGoreleaserBuilds(t, yaml)

	var primary *goreleaserBuild
	for i := range builds {
		if builds[i].main == "./cmd/obsigna" {
			primary = &builds[i]
		}
		// No build may ship the obsigna source under the agent-receipts name.
		if builds[i].main == "./cmd/obsigna" && builds[i].binary == "agent-receipts" {
			t.Errorf("build %q ships ./cmd/obsigna as binary agent-receipts; the primary CLI must be 'obsigna'", builds[i].id)
		}
		// Anything named agent-receipts must be the shim package.
		if builds[i].binary == "agent-receipts" && builds[i].main != "./cmd/agent-receipts" {
			t.Errorf("build %q ships binary agent-receipts from %q; only ./cmd/agent-receipts (the shim) may", builds[i].id, builds[i].main)
		}
	}
	if primary == nil {
		t.Fatal("no goreleaser build builds ./cmd/obsigna — the primary CLI is missing")
	}
	if primary.binary != "obsigna" {
		t.Errorf("primary CLI binary = %q, want \"obsigna\"", primary.binary)
	}
}

// TestShimDoesNotReimplementSurface keeps cmd/agent-receipts a thin forwarder: it
// must carry the shim marker and must NOT import the subcommand packages (which
// would mean it had grown its own command surface again).
func TestShimDoesNotReimplementSurface(t *testing.T) {
	src := readFile(t, "../agent-receipts/main.go")
	if !strings.Contains(src, "agent-receipts-deprecation-shim") {
		t.Error("cmd/agent-receipts is missing the deprecation-shim marker; it must remain a forwarding shim")
	}
	for _, pkg := range []string{
		"internal/verifycli", "internal/showcli", "internal/listcli",
		"internal/verifyeventcli", "internal/doctorcli", "internal/keyscli",
	} {
		if strings.Contains(src, pkg) {
			t.Errorf("cmd/agent-receipts imports %q — the shim must forward to obsigna, not re-implement the surface", pkg)
		}
	}
}

// TestObsignaRegistersSurface is the converse: obsigna is the real CLI, so it must
// wire the subcommand packages.
func TestObsignaRegistersSurface(t *testing.T) {
	src := readFile(t, "registry.go")
	for _, pkg := range []string{"internal/verifycli", "internal/keyscli", "internal/doctorcli"} {
		if !strings.Contains(src, pkg) {
			t.Errorf("cmd/obsigna registry does not wire %q; obsigna must be the primary CLI", pkg)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
