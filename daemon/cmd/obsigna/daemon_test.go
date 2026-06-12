package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// attestRoleEnv switches this test binary into a helper role for
// TestDaemonRunPreservesAttestationTuple. When set to "launcher", TestMain
// behaves as `obsigna daemon run` and execs the daemon in place, so the
// subprocess exercises the real syscall.Exec path rather than a stub.
const attestRoleEnv = "OBSIGNA_TEST_ROLE"

// stubDaemonSource is a throwaway obsigna-daemon: it prints its own attestation
// tuple (pid, parent pid, resolved executable path) as JSON and exits. The
// acceptance test execs into it and checks the tuple survived the launch.
const stubDaemonSource = `package main

import (
	"encoding/json"
	"os"
)

func main() {
	exe, _ := os.Executable()
	// On Linux this is the authoritative attestation source; on platforms
	// without /proc it fails and we keep os.Executable()'s answer.
	if resolved, err := os.Readlink("/proc/self/exe"); err == nil {
		exe = resolved
	}
	enc, _ := json.Marshal(map[string]any{
		"pid":  os.Getpid(),
		"ppid": os.Getppid(),
		"exe":  exe,
	})
	os.Stdout.Write(enc)
}
`

func TestMain(m *testing.M) {
	// Launcher role: stand in for `obsigna daemon run` and exec the daemon
	// binary, replacing this image. resolveDaemonBinary finds the stub via the
	// PATH the parent test set. This never returns when the exec succeeds.
	if os.Getenv(attestRoleEnv) == "launcher" {
		os.Exit(execDaemon(nil, os.Stderr))
	}
	os.Exit(m.Run())
}

// TestExecImageDefaultsToSyscallExec is the non-negotiable invariant from
// ADR-0031: the launcher replaces its image, it never forks. exec.Command would
// reparent the daemon under obsigna and corrupt the parent-PID leg of the
// attestation tuple, so guard the wiring rather than trusting a comment.
func TestExecImageDefaultsToSyscallExec(t *testing.T) {
	if reflect.ValueOf(execImage).Pointer() != reflect.ValueOf(syscall.Exec).Pointer() {
		t.Error("execImage must default to syscall.Exec; forking (exec.Command) would break the attestation tuple (ADR-0031)")
	}
}

// TestRunDaemonRunExecsResolvedBinary checks the launch wiring without a real
// exec: `run` resolves obsigna-daemon, builds argv[0]=binary + forwarded flags,
// and passes the inherited environment through.
func TestRunDaemonRunExecsResolvedBinary(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, obsignaDaemonBinary)
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH-only resolution: the test binary's own dir has no obsigna-daemon, so
	// resolveDaemonBinary falls through to this stub on PATH.
	t.Setenv("PATH", dir)

	var gotArgv0 string
	var gotArgv, gotEnv []string
	orig := execImage
	execImage = func(argv0 string, argv, envv []string) error {
		gotArgv0, gotArgv, gotEnv = argv0, argv, envv
		return nil // pretend the exec succeeded; the real one never returns
	}
	t.Cleanup(func() { execImage = orig })

	code := runDaemon([]string{"run", "--socket", "/tmp/x.sock"}, io.Discard, io.Discard)
	if code != exitOK {
		t.Fatalf("runDaemon run exit = %d, want %d", code, exitOK)
	}
	if gotArgv0 != stub {
		t.Errorf("argv0 = %q, want %q (resolved beside obsigna / on PATH)", gotArgv0, stub)
	}
	if want := []string{stub, "--socket", "/tmp/x.sock"}; !reflect.DeepEqual(gotArgv, want) {
		t.Errorf("argv = %v, want %v", gotArgv, want)
	}
	if len(gotEnv) == 0 {
		t.Error("exec env is empty; the daemon must inherit obsigna's environment across the exec")
	}
}

// TestRunDaemonUsage covers the launcher's non-exec paths: a bare `daemon` and
// an unknown subcommand are usage errors that name `daemon run`; `-h` prints
// help and exits 0.
func TestRunDaemonUsage(t *testing.T) {
	var errb bytes.Buffer
	if code := runDaemon(nil, io.Discard, &errb); code != exitUsageError {
		t.Errorf("bare daemon exit = %d, want %d", code, exitUsageError)
	}
	if !strings.Contains(errb.String(), "obsigna daemon run") {
		t.Errorf("bare daemon stderr = %q, want it to mention `obsigna daemon run`", errb.String())
	}

	var out bytes.Buffer
	if code := runDaemon([]string{"-h"}, &out, io.Discard); code != exitOK {
		t.Errorf("daemon -h exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out.String(), "obsigna daemon run") {
		t.Errorf("daemon -h stdout = %q, want usage", out.String())
	}

	errb.Reset()
	if code := runDaemon([]string{"frobnicate"}, io.Discard, &errb); code != exitUsageError {
		t.Errorf("unknown daemon subcommand exit = %d, want %d", code, exitUsageError)
	}
	if !strings.Contains(errb.String(), "unknown subcommand") {
		t.Errorf("unknown daemon subcommand stderr = %q, want it to report the unknown subcommand", errb.String())
	}
}

// TestDaemonRunPreservesAttestationTuple is the ADR-0031 acceptance test: after
// `obsigna daemon run`, the daemon must run AS the launcher (same PID, image
// replaced — not a forked child), keep the launcher's parent (systemd in
// production, this test process here), and expose obsigna-daemon as its
// executable. It re-runs this test binary in the launcher role; that helper
// execs a freshly built stub daemon which reports its own tuple.
func TestDaemonRunPreservesAttestationTuple(t *testing.T) {
	binDir := t.TempDir()
	daemonPath := filepath.Join(binDir, obsignaDaemonBinary)
	buildStubDaemon(t, daemonPath)

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}

	cmd := exec.Command(self)
	// PATH points only at the stub dir so the launcher resolves our stub; the
	// role var makes TestMain take the launcher branch and exec it.
	cmd.Env = append(os.Environ(), attestRoleEnv+"=launcher", "PATH="+binDir)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	launcherPID := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("launcher exited with error: %v\nstderr: %s", err, errb.String())
	}

	var got struct {
		PID  int    `json:"pid"`
		PPID int    `json:"ppid"`
		Exe  string `json:"exe"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("parse daemon tuple %q: %v (stderr: %s)", out.String(), err, errb.String())
	}

	// Image replaced, not forked: the daemon runs under the launcher's own PID.
	if got.PID != launcherPID {
		t.Errorf("daemon pid = %d, launcher pid = %d; want equal — syscall.Exec replaces the image, it must not fork a child", got.PID, launcherPID)
	}
	// The daemon's parent is the launcher's parent (this test = the supervisor),
	// never an intervening obsigna process.
	if got.PPID != os.Getpid() {
		t.Errorf("daemon ppid = %d, want %d (the launcher's parent, i.e. systemd in production)", got.PPID, os.Getpid())
	}
	// The attestation identity resolves to obsigna-daemon.
	if base := filepath.Base(got.Exe); base != obsignaDaemonBinary {
		t.Errorf("daemon exe = %q (base %q), want base %q", got.Exe, base, obsignaDaemonBinary)
	}
}

// buildStubDaemon compiles stubDaemonSource into a binary at outPath named
// obsigna-daemon. The single stdlib-only file builds standalone from a temp dir
// outside the module, so it needs no go.mod.
func buildStubDaemon(t *testing.T, outPath string) {
	t.Helper()
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(src, []byte(stubDaemonSource), 0o644); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", outPath, src)
	build.Dir = srcDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build stub daemon: %v\n%s", err, out)
	}
}
