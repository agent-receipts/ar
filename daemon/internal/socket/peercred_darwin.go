//go:build darwin

package socket

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// capturePeer reads LOCAL_PEERCRED + LOCAL_PEEREPID off the connected socket.
// Captured at accept() time, before any frame is read, so a forking emitter
// cannot mislabel itself.
//
// macOS LOCAL_PEERCRED returns an xucred whose Groups[0] is the effective gid;
// LOCAL_PEEREPID returns the effective pid (xucred itself does not carry pid).
//
// ExePath is left empty on Phase 1 — proc_pidpath requires CGO or a raw
// libSystem call and is deferred to a follow-up.
func capturePeer(conn *net.UnixConn) (PeerCred, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return PeerCred{}, fmt.Errorf("syscall conn: %w", err)
	}

	pc := PeerCred{Platform: "darwin"}

	var inner error
	ctlErr := rc.Control(func(fd uintptr) {
		xu, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			inner = fmt.Errorf("LOCAL_PEERCRED: %w", err)
			return
		}
		// xu.Uid is uint32; xu.Groups elements are uint32. PeerCred.UID/GID
		// are uint32 too — direct assignment, no narrowing.
		pc.UID = xu.Uid
		if xu.Ngroups > 0 {
			pc.GID = xu.Groups[0]
		}

		pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEEREPID)
		if err != nil {
			inner = fmt.Errorf("LOCAL_PEEREPID: %w", err)
			return
		}
		pc.PID = int32(pid)
	})
	if ctlErr != nil {
		return PeerCred{}, fmt.Errorf("control: %w", ctlErr)
	}
	if inner != nil {
		return PeerCred{}, inner
	}
	return pc, nil
}
