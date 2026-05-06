//go:build darwin

package socket

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// proc_info constants from <sys/proc_info.h>.
//
// libproc's proc_pidpath(3) is a thin wrapper around the SYS_PROC_INFO
// syscall (number 336, exported as unix.SYS_PROC_INFO). We reimplement the
// wrapper directly rather than taking a CGO dependency on libproc — the
// daemon ships with CGO disabled, and the syscall ABI is stable kernel
// contract: changing these constants would break every binary on macOS.
const (
	procInfoCallPIDInfo    = 0x2  // PROC_INFO_CALL_PIDINFO
	procPIDPathInfo        = 11   // PROC_PIDPATHINFO flavor
	procPIDPathInfoMaxSize = 4096 // PROC_PIDPATHINFO_MAXSIZE = 4 * MAXPATHLEN
)

// capturePeer reads LOCAL_PEERCRED + LOCAL_PEEREPID off the connected socket
// and resolves the peer's executable via proc_pidpath. Captured at accept()
// time, before any frame is read, so a forking emitter cannot mislabel
// itself.
//
// macOS LOCAL_PEERCRED returns an xucred whose Groups[0] is the effective gid;
// LOCAL_PEEREPID returns the effective pid (xucred itself does not carry pid).
//
// Unlike Linux's SO_PEERCRED — which snapshots the ucred at connect time and
// remains readable after the peer detaches — macOS's LOCAL_PEEREPID reads the
// live peer's pcb and returns ENOTCONN once the peer has closed its end. With
// rapid connect → write → close patterns (one connection per frame), the peer
// often disconnects between accept() and our getsockopt call. We treat
// ENOTCONN as "pid unresolved": uid/gid still come from the cached xucred
// (which LOCAL_PEERCRED captures at connect time, so it survives peer
// detachment), and the frame still gets processed. PID and exe_path stay zero
// for that record, mirroring the existing tolerance for an unreadable
// /proc/<pid>/exe on Linux.
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
			if errors.Is(err, unix.ENOTCONN) {
				// Peer detached between accept() and getsockopt; pid stays 0.
				return
			}
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

	// Resolve exe_path. Failure is non-fatal: the daemon still records
	// pid/uid/gid and exe_path stays empty, mirroring the Linux path which
	// also tolerates an unreadable /proc/<pid>/exe. Skip when pid is unknown
	// (LOCAL_PEEREPID returned ENOTCONN above) — proc_pidpath(0) would target
	// the kernel.
	if pc.PID > 0 {
		pc.ExePath = resolveExePath(pc.PID)
	}

	return pc, nil
}

// resolveExePath returns the absolute executable path for the given pid by
// invoking the SYS_PROC_INFO(PROC_PIDPATHINFO) syscall — the same call
// libproc's proc_pidpath() makes. Returns "" on any failure (process exited,
// caller lacks permission, etc.); callers treat an empty string as "could
// not resolve" rather than surfacing the syscall error, mirroring Linux's
// os.Readlink behaviour in peercred_linux.go.
func resolveExePath(pid int32) string {
	var buf [procPIDPathInfoMaxSize]byte
	n, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		uintptr(procInfoCallPIDInfo),
		uintptr(pid),
		uintptr(procPIDPathInfo),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 || n == 0 {
		return ""
	}
	// proc_pidpath copies a NUL-terminated path; the syscall returns the byte
	// count including the trailing NUL. ByteSliceToString trims at the first
	// NUL and is robust against a missing terminator.
	if n > uintptr(len(buf)) {
		// Defensive: kernel reported more bytes than the buffer holds. Should
		// be impossible (proc_pidpath caps at PROC_PIDPATHINFO_MAXSIZE), but
		// don't let buf[:n] panic if it ever happens. Compare in uintptr
		// space so a wrapped sentinel doesn't slip past as a negative int.
		return ""
	}
	return unix.ByteSliceToString(buf[:n])
}
