// Package host detects the MCP host (Claude Code, Codex, Cursor, Windsurf,
// etc.) that launched this proxy process and returns its issuer/operator
// identity for stamping on every emitted receipt.
package host

// Identity is what the proxy reports to the daemon about the host that launched it.
type Identity struct {
	IssuerName   string // e.g. "Claude Code"
	IssuerModel  string // optional, e.g. ""
	OperatorID   string // e.g. "did:web:anthropic.com"
	OperatorName string // e.g. "Anthropic"
	Source       string // "auto:<key>" | "flags" | "unknown" — for logging only
}

// registry maps parent process comm names to their known Identity.
var registry = map[string]Identity{
	"claude": {
		IssuerName:   "Claude Code",
		OperatorID:   "did:web:anthropic.com",
		OperatorName: "Anthropic",
	},
	"codex": {
		IssuerName:   "Codex",
		OperatorID:   "did:web:openai.com",
		OperatorName: "OpenAI",
	},
	"cursor": {
		IssuerName:   "Cursor",
		OperatorID:   "did:web:cursor.com",
		OperatorName: "Cursor",
	},
	"windsurf": {
		IssuerName:   "Windsurf",
		OperatorID:   "did:web:codeium.com",
		OperatorName: "Codeium",
	},
}
