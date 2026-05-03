// Package socket owns the daemon's Unix-domain-socket listener, the per-OS
// peer-credential capture, and the length-prefix message framing.
//
// ADR-0010 specifies SOCK_SEQPACKET, but macOS does not support SEQPACKET on
// AF_UNIX (only SOCK_STREAM and SOCK_DGRAM). Phase 1 uses SOCK_STREAM uniformly
// on Linux and macOS with a 4-byte big-endian length prefix per frame. Peer
// credentials are still reliably retrievable on stream sockets via
// SO_PEERCRED (Linux) / LOCAL_PEERCRED + LOCAL_PEEREPID (macOS), so the
// transport simplification does not affect the trust model. A follow-up issue
// should amend ADR-0010 to record the per-OS transport types.
package socket

// PeerCred is the OS-attested identity of a connecting emitter, captured at
// accept() time before any frame is read. The agent's self-asserted identity
// in the frame body is untrusted; this is what makes the audit meaningful.
type PeerCred struct {
	// Platform discriminates which fields are populated. One of
	// "linux", "darwin". A future Windows port will introduce additional
	// values and fields (user_sid, integrity_level).
	Platform string

	// PID is the connecting process's process id.
	PID int32

	// UID, GID are POSIX credentials. Always populated on linux and darwin.
	UID int32
	GID int32

	// ExePath is the absolute path to the connecting process's executable,
	// or "" when the daemon could not resolve it. On Linux this is read from
	// /proc/<pid>/exe. On macOS Phase 1 leaves this empty — proc_pidpath
	// requires CGO or a raw libSystem syscall and is out of scope here.
	ExePath string
}
