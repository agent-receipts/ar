//go:build !linux && !darwin

package socket

import (
	"fmt"
	"net"
	"runtime"
)

// capturePeer is a build-only stub for platforms outside Phase 1 scope
// (Phase 1 ships Linux and macOS; Windows named pipes are tracked as a
// separate issue per #236). The daemon refuses to start on these platforms
// rather than silently producing receipts without peer attestation.
func capturePeer(_ *net.UnixConn) (PeerCred, error) {
	return PeerCred{}, fmt.Errorf("agent-receipts-daemon: peer credential capture not implemented on %s", runtime.GOOS)
}
