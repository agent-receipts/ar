package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// obsignaDaemonBinary is the daemon image `obsigna daemon run` launches.
// ADR-0031: the daemon is its own minimal binary so the attestation tuple it
// exposes — /proc/self/exe, parent PID, start time — describes the daemon
// itself, not the launcher that started it.
const obsignaDaemonBinary = "obsigna-daemon"

// execImage replaces the current process image with the named binary, the way
// execve(2) does. It is a package var so tests can both stub it and assert that
// it defaults to syscall.Exec.
//
// This MUST be syscall.Exec, never exec.Command: forking a child would make
// obsigna the daemon's parent instead of systemd, so the daemon's parent PID
// (part of the attestation tuple ADR-0031 preserves) would point at a launcher
// that has already exited rather than the supervisor. Replacing the image keeps
// the PID, the parent PID, the start time, and the inherited stdio/fds intact —
// the running daemon is indistinguishable from one systemd exec'd directly.
var execImage = syscall.Exec

// runDaemon implements `obsigna daemon <subcommand>`. The sole subcommand is
// `run`, which execs obsigna-daemon in place and forwards the remaining args.
// The getenv-less signature is deliberate: the daemon inherits obsigna's
// environment wholesale across the exec, so there is nothing to look up here.
func runDaemon(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, daemonUsage())
		return exitUsageError
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, daemonUsage())
		return exitOK
	case "run":
		return execDaemon(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "obsigna daemon: unknown subcommand %q\n\n%s", args[0], daemonUsage())
		return exitUsageError
	}
}

// execDaemon resolves the obsigna-daemon binary and replaces this process with
// it, forwarding args and the current environment. On success it does not
// return — the image is gone. A return means the exec never happened (binary
// missing or not executable); that is the only error path.
func execDaemon(args []string, stderr io.Writer) int {
	bin, err := resolveDaemonBinary()
	if err != nil {
		fmt.Fprintf(stderr, "obsigna daemon run: %v\n", err)
		return 1
	}
	// argv[0] is the resolved daemon path so ps/`/proc/self/cmdline` show
	// obsigna-daemon, not obsigna. The daemon parses os.Args[1:] exactly as if
	// invoked directly.
	argv := append([]string{bin}, args...)
	if err := execImage(bin, argv, os.Environ()); err != nil {
		fmt.Fprintf(stderr, "obsigna daemon run: exec %s: %v\n", bin, err)
		return 1
	}
	return exitOK // unreachable with the real syscall.Exec; the image is replaced
}

// resolveDaemonBinary locates obsigna-daemon. It prefers a binary installed
// alongside obsigna (the goreleaser/Homebrew layout drops both into one bin
// dir), falling back to $PATH. Resolving beside obsigna first avoids picking up
// an unrelated obsigna-daemon earlier on PATH. Mirrors the shim's resolver in
// cmd/agent-receipts.
func resolveDaemonBinary() (string, error) {
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), obsignaDaemonBinary)
		if isExecutableFile(candidate) {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath(obsignaDaemonBinary); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("cannot locate the %q binary (expected next to obsigna or on $PATH)", obsignaDaemonBinary)
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// daemonUsage is the help for the daemon launcher subtree.
func daemonUsage() string {
	return "Usage: obsigna daemon run [daemon flags]\n\n" +
		"Replace this process with obsigna-daemon (ADR-0031), forwarding any flags\n" +
		"and the current environment. In production, systemd's ExecStart should point\n" +
		"straight at obsigna-daemon; `obsigna daemon run` is the same image via PATH.\n"
}
