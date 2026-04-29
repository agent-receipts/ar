// fakeserver is a minimal JSON-RPC MCP server used in proxy tests.
//
// It reads newline-delimited JSON-RPC requests from stdin and writes back a
// trivial success response for each one that carries an "id" field.
//
// Environment variable MAX_RESPONSES controls how many responses to emit before
// exiting (default: unlimited). This is used to simulate upstream death midway.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

func main() {
	max := -1 // unlimited
	if s := os.Getenv("MAX_RESPONSES"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fakeserver: bad MAX_RESPONSES %q: %v\n", s, err)
			os.Exit(1)
		}
		max = n
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	sent := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		var req map[string]json.RawMessage
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		id, hasID := req["id"]
		if !hasID {
			continue // notification — no response needed
		}

		if max >= 0 && sent >= max {
			// Simulate upstream dying — exit without responding.
			os.Exit(0)
		}

		resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{}}`, string(id))
		fmt.Println(resp)
		sent++
	}
}
