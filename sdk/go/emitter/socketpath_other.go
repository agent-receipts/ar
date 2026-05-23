//go:build !darwin && !linux

package emitter

// platformDefaultSocketPath returns the empty string on platforms the
// daemon does not support. Callers must pass an explicit socket path
// via WithSocketPath; AGENTRECEIPTS_SOCKET is ignored here so an
// unsupported-platform run fails clearly at New rather than producing
// a path that points nowhere.
func platformDefaultSocketPath() string {
	return ""
}
