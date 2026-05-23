//go:build !darwin && !linux

package emitter

// platformDefaultSocketPath returns the empty string on platforms the
// daemon does not support. AGENTRECEIPTS_SOCKET is consulted by the
// caller (DefaultSocketPath) before reaching this function, so an
// explicit env override still produces a usable path on these hosts;
// only the auto-detected default is empty. Callers without an override
// must pass an explicit socket path via WithSocketPath, and New will
// raise a clear error if none is supplied.
func platformDefaultSocketPath() string {
	return ""
}
