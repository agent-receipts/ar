//go:build !unix

package doctorcli

import "os"

// ownerString has no portable owner concept off unix; the daemon only runs on
// linux/darwin, but the read CLI must still cross-compile.
func ownerString(info os.FileInfo) string {
	return "owner unknown"
}
