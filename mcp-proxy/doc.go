// Package mcpproxy is the Agent Receipts MCP proxy module.
//
// The mcp-proxy command (cmd/mcp-proxy) sits between MCP clients and upstream MCP
// servers. It enforces policy, records audit events, and can require human approval
// before forwarding tool calls.
//
// Implementation packages live under internal/ and are intended for use by this
// module only.
package mcpproxy
