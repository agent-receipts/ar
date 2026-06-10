//go:build integration && (linux || darwin)

package daemon

import (
	"os"
	"testing"
	"time"
)

// TestPeerCredFromSDKSubprocesses verifies the daemon captures the OS-attested
// peer credential of each non-Go SDK emitter — the TypeScript (Node) and Python
// (uv) subprocesses — not just the in-process Go library path.
//
// integration_test.go already covers peer-cred capture for the Go library
// (TestPeerCredCaptured) and a re-exec'd Go subprocess (TestPeerCredFromSubprocess).
// This closes the remaining cross-emitter gap: a regression in how the daemon
// reads SO_PEERCRED / LOCAL_PEEREPID could pass the Go tests yet silently drop
// the credential for connections opened by node or python. Because each emitter
// runs as a distinct OS process, its recorded pid must differ from the test
// process's pid and never be zero, and its uid must match the test user.
func TestPeerCredFromSDKSubprocesses(t *testing.T) {
	cases := []struct {
		name string
		emit func(t *testing.T, f *DaemonFixture, sessionID string) error
	}{
		{
			name: "ts",
			emit: func(t *testing.T, f *DaemonFixture, sessionID string) error {
				return f.EmitTSFrame(t, sessionID, "sdk", "test-tool", "allowed")
			},
		},
		{
			name: "python",
			emit: func(t *testing.T, f *DaemonFixture, sessionID string) error {
				return f.EmitPythonFrame(t, sessionID, "sdk", "test-tool", "allowed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := StartDaemon(t)

			if err := tc.emit(t, f, tc.name+"-peercred"); err != nil {
				t.Fatalf("emit failed: %v", err)
			}

			receipts := f.WaitForReceiptCount(t, 1, 5*time.Second)
			pc := receipts[0].CredentialSubject.Action.PeerCredential
			if pc == nil {
				t.Fatalf("PeerCredential nil; daemon must record OS-attested peer cred for %s subprocess\ntrace:\n%s",
					tc.name, f.Trace())
			}

			// The emitter ran as a separate process, so its pid must differ from
			// this test process and must be a real (non-zero) pid. A regression
			// that recorded the listener's own pid would trip the first check.
			if pc.PID == int32(os.Getpid()) {
				t.Errorf("peer_credential.pid = %d (= os.Getpid()); daemon recorded the listener's pid, not the %s subprocess's",
					pc.PID, tc.name)
			}
			if pc.PID == 0 {
				t.Errorf("peer_credential.pid is 0 — peer-cred capture failed for %s subprocess", tc.name)
			}

			// Same user runs the subprocess, so the uid must match.
			wantUID := uint32(os.Geteuid())
			if pc.UID == nil || *pc.UID != wantUID {
				t.Errorf("peer_credential.uid = %v, want %d", pc.UID, wantUID)
			}

			switch pc.Platform {
			case "linux":
				// Linux resolves /proc/<pid>/exe, which must point at the
				// subprocess interpreter (node / python) — never this test
				// binary. os.SameFile tolerates symlink/canonicalisation diffs.
				if pc.ExePath == "" {
					t.Error("Linux daemon should populate peer_credential.exe_path from /proc/<pid>/exe")
				} else {
					assertNotTestBinary(t, pc.ExePath)
				}
			case "darwin":
				// SYS_PROC_INFO may be restricted in sandboxed CI; the daemon
				// degrades gracefully (pid/uid still recorded). Only assert
				// when a path was resolved.
				if pc.ExePath == "" {
					t.Log("darwin: peer_credential.exe_path empty; SYS_PROC_INFO may be restricted in this environment")
				} else {
					assertNotTestBinary(t, pc.ExePath)
				}
			default:
				t.Errorf("unexpected peer_credential.platform = %q", pc.Platform)
			}
		})
	}
}

// assertNotTestBinary fails if exePath refers to the running test binary. The
// connecting peer is an external interpreter (node/python), so a captured
// exe_path that matches os.Executable means the daemon recorded its own
// process's path instead of the connecting peer's.
func assertNotTestBinary(t *testing.T, exePath string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exeInfo, err := os.Stat(exePath)
	if err != nil {
		t.Fatalf("os.Stat(peer_credential.exe_path %q): %v", exePath, err)
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		t.Fatalf("os.Stat(os.Executable %q): %v", self, err)
	}
	if os.SameFile(exeInfo, selfInfo) {
		t.Errorf("peer_credential.exe_path = %q is the test binary; daemon recorded its own process, not the connecting subprocess", exePath)
	}
}
