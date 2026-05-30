// Command mcp-proxy sits between an MCP client and an MCP server, transparently
// intercepting every tool call to classify it, evaluate YAML policy rules
// (pass/flag/pause/block), run optional approval workflows, and forward
// completed events to the agent-receipts daemon for signing and persistence.
//
// Usage:
//
//	mcp-proxy [flags] <command> [args...]
//	mcp-proxy serve   [flags] <command> [args...]
//	mcp-proxy doctor  [-rules <file>] [-approver <url>] [-json]
//	mcp-proxy init    [-name <name>] [-http-port <port>] [-no-approval]
//
// The default subcommand is serve, which wraps the given MCP server command
// and proxies its stdin/stdout, applying policy and emitting receipts.
//
// See https://agentreceipts.ai/mcp-proxy/ for full documentation.
package main
