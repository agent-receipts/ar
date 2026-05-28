//go:build unix

package doctorcli

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// ownerString renders the file's owner uid and group (resolving the group name
// when possible) for human-readable reasons. ADR-0010 § Read interface expects
// the receipt DB to be group-readable via group "agentreceipts-read"; surfacing
// the group lets an operator confirm that without a separate stat.
func ownerString(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "owner unknown"
	}
	group := strconv.FormatUint(uint64(st.Gid), 10)
	if g, err := user.LookupGroupId(group); err == nil {
		group = g.Name
	}
	return fmt.Sprintf("uid %d, group %s", st.Uid, group)
}
