//go:build linux

package socket

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// capturePeer reads SO_PEERCRED off the connected socket and resolves the
// peer's executable via /proc/<pid>/exe. Captured at accept() time, before
// any frame is read, so a forking emitter cannot mislabel itself.
func capturePeer(conn *net.UnixConn) (PeerCred, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return PeerCred{}, fmt.Errorf("syscall conn: %w", err)
	}

	var pc PeerCred
	pc.Platform = "linux"

	var ucredErr error
	ctlErr := rc.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			ucredErr = fmt.Errorf("SO_PEERCRED: %w", err)
			return
		}
		pc.PID = ucred.Pid
		// ucred.Uid/Gid are uint32; PeerCred.UID/GID are uint32 too. Direct
		// assignment with no narrowing.
		pc.UID = ucred.Uid
		pc.GID = ucred.Gid
	})
	if ctlErr != nil {
		return PeerCred{}, fmt.Errorf("control: %w", ctlErr)
	}
	if ucredErr != nil {
		return PeerCred{}, ucredErr
	}

	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pc.PID)); err == nil {
		pc.ExePath = exe
	}
	return pc, nil
}
