// Command agent-receipts is the daemon's read-side companion CLI. Logic lives
// in internal/verifycli and internal/listcli so subcommands can be tested
// without shelling out to the binary.
package main

import (
	"fmt"
	"os"

	"github.com/agent-receipts/ar/daemon/internal/listcli"
	"github.com/agent-receipts/ar/daemon/internal/verifycli"
)

const usage = `Usage: agent-receipts <command> [flags]

Commands:
  list     List recent receipts from the store.
  verify   Verify a stored chain's signatures and hash links.

Run 'agent-receipts <command> -h' for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(verifycli.ExitUsageError)
	}
	switch os.Args[1] {
	case "list":
		os.Exit(listcli.Run(os.Args[2:], os.Stdout, os.Stderr, os.Getenv))
	case "verify":
		os.Exit(verifycli.Run(os.Args[2:], os.Stdout, os.Stderr, os.Getenv))
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		os.Exit(verifycli.ExitOK)
	default:
		fmt.Fprintf(os.Stderr, "agent-receipts: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(verifycli.ExitUsageError)
	}
}
