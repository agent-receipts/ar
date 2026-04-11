package audit

import (
	"encoding/json"
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

// Sensitive JSON keys (case-insensitive).
var sensitiveKeys = map[string]bool{
	"password":          true,
	"token":             true,
	"api_key":           true,
	"apikey":            true,
	"secret":            true,
	"authorization":     true,
	"private_key":       true,
	"privatekey":        true,
	"access_token":      true,
	"refresh_token":     true,
	"client_secret":     true,
	"credentials":       true,
	"session_token":     true,
	"session_id":        true,
	"sessionid":         true,
	"auth_token":        true,
	"cookie":            true,
	"set-cookie":        true,
	"x-api-key":         true,
	"bearer":            true,
	"jwt":               true,
	"signing_key":       true,
	"encryption_key":    true,
	"database_url":      true,
	"connection_string": true,
	"dsn":               true,
	"ssh_key":           true,
	"passphrase":        true,
	"pin":               true,
}

// Pattern-based redaction for common secret formats.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),             // GitHub PAT
	regexp.MustCompile(`gho_[A-Za-z0-9]{36,}`),             // GitHub OAuth
	regexp.MustCompile(`sk-[A-Za-z0-9\-]{20,}`),            // OpenAI/Anthropic
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),                 // AWS access key
	regexp.MustCompile(`Bearer\s+[A-Za-z0-9._\-/+=]{20,}`), // Bearer tokens
	regexp.MustCompile(`xox[bpras]-[A-Za-z0-9\-]+`),        // Slack tokens
	// PEM private keys: match the entire block from BEGIN to END.
	regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----`),
}

// Redact removes sensitive data from a JSON string.
// First applies JSON-aware key redaction, then pattern-based fallback.
func Redact(raw string) string {
	// Try JSON-aware redaction.
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		redacted := redactValue(parsed)
		if b, err := json.Marshal(redacted); err == nil {
			raw = string(b)
		}
	}

	// Pattern-based redaction as second pass.
	for _, pat := range secretPatterns {
		raw = pat.ReplaceAllString(raw, redacted)
	}

	return raw
}

func redactValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, v := range val {
			if sensitiveKeys[strings.ToLower(k)] {
				out[k] = redacted
			} else {
				out[k] = redactValue(v)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = redactValue(item)
		}
		return out
	default:
		return v
	}
}
