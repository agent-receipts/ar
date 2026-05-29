//go:build linux

package host

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// readComm reads the comm name for the given pid from /proc/<pid>/comm.
// Swapped in tests to avoid real /proc reads.
var readComm = func(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimRight(string(b), "\n")), nil
}

// environ lists the process environment as "KEY=VALUE" strings.
// Swapped in tests to avoid depending on the real environment.
var environ = os.Environ

// envMarkers map a host's environment-variable signal to its registry key, used
// as a secondary signal when /proc gives no useful result. A marker matches by
// exact variable name, or by name prefix for variable families (WINDSURF_*,
// CODEX_*). Markers are checked in declared order, so earlier hosts win when a
// process sets signals for more than one.
var envMarkers = []struct {
	name   string // exact variable name, or prefix when prefix is true
	prefix bool   // match name as a prefix (variable families)
	key    string // registry key; must exist in registry (asserted by tests)
}{
	{name: "CLAUDECODE", key: "claude"},
	{name: "CURSOR_TRACE_ID", key: "cursor"},
	{name: "WINDSURF_", prefix: true, key: "windsurf"},
	{name: "CODEX_", prefix: true, key: "codex"},
}

// Detect inspects the parent process name via /proc/<ppid>/comm and returns the
// best-guess Identity. A registry hit yields Source "auto:<comm>". When /proc
// gives no useful result — the parent comm is unknown (e.g. aliased by a
// wrapper shell) or unreadable — detection falls through to an environment
// marker scan, yielding Source "env:<var>". Source is "unknown" when neither
// signal matches.
func Detect() Identity {
	if comm, err := readComm(os.Getppid()); err == nil {
		if id, ok := registry[comm]; ok {
			id.Source = "auto:" + comm
			return id
		}
	}
	if id, ok := detectEnv(); ok {
		return id
	}
	return Identity{Source: "unknown"}
}

// detectEnv scans the environment for known host markers, returning the
// matching Identity (Source "env:<var>") and true on the first hit, or a zero
// Identity and false when none match. The environment is sorted first so a
// family marker that matches several variables reports a stable Source.
func detectEnv() (Identity, bool) {
	env := environ()
	slices.Sort(env)
	for _, m := range envMarkers {
		id, ok := registry[m.key]
		if !ok {
			continue // misconfigured marker: no registry entry to stamp
		}
		for _, kv := range env {
			name, _, _ := strings.Cut(kv, "=")
			if name == m.name || (m.prefix && strings.HasPrefix(name, m.name)) {
				id.Source = "env:" + name
				return id, true
			}
		}
	}
	return Identity{}, false
}
