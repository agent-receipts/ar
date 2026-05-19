//go:build linux

package host

import (
	"fmt"
	"os"
	"strings"
)

// readComm reads the comm name for the given pid from /proc/<pid>/comm.
// Swapped in tests to avoid real /proc reads.
var readComm = func(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

// Detect inspects the parent process name via /proc/<ppid>/comm and returns
// the best-guess Identity. Source is "auto:<key>" on a registry hit, or
// "unknown" when the parent process is not in the built-in registry.
//
// TODO: consider env-marker secondary checks for cases where /proc gives no
// useful result (e.g. process name aliased by a wrapper shell):
//   - CLAUDECODE (Claude Code SDK)
//   - CURSOR_TRACE_ID (Cursor)
//   - WINDSURF_* (Windsurf)
//   - CODEX_* (OpenAI Codex)
func Detect() Identity {
	comm, err := readComm(os.Getppid())
	if err != nil {
		return Identity{Source: "unknown"}
	}
	id, ok := registry[comm]
	if !ok {
		return Identity{Source: "unknown"}
	}
	id.Source = "auto:" + comm
	return id
}
