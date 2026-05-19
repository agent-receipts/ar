//go:build !linux

package host

// Detect returns an empty Identity on non-Linux platforms. /proc-based parent
// process detection is Linux-only for v1; flags and env vars are the
// recommended override mechanism on macOS and Windows.
func Detect() Identity {
	return Identity{Source: "unknown"}
}
