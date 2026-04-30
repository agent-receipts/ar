package audit

import (
	"encoding/json"
	"fmt"
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

// NamedPattern is a compiled regular expression with a stable name.
type NamedPattern struct {
	Name string
	Re   *regexp.Regexp
}

// builtinPatterns is the ordered set of named patterns applied by the default
// Redactor. The slice is unexported to prevent callers from mutating it and
// silently weakening redaction; use BuiltinPatterns() to obtain a safe copy.
var builtinPatterns = []NamedPattern{
	{
		Name: "github-pat-classic",
		Re:   regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
	},
	{
		Name: "github-pat-finegrained",
		Re:   regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`),
	},
	{
		Name: "github-oauth",
		Re:   regexp.MustCompile(`gho_[A-Za-z0-9]{36,}`),
	},
	{
		Name: "github-app-installation",
		Re:   regexp.MustCompile(`ghs_[A-Za-z0-9]{36,}`),
	},
	{
		Name: "github-user-to-server",
		Re:   regexp.MustCompile(`ghu_[A-Za-z0-9]{36,}`),
	},
	{
		Name: "github-installation-legacy",
		Re:   regexp.MustCompile(`v1\.[a-f0-9]{40,}`),
	},
	{
		Name: "openai-anthropic-key",
		Re:   regexp.MustCompile(`sk-[A-Za-z0-9\-]{20,}`),
	},
	{
		Name: "aws-access-key",
		Re:   regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	},
	{
		Name: "bearer-token",
		Re:   regexp.MustCompile(`Bearer\s+[A-Za-z0-9._\-/+=]{20,}`),
	},
	{
		Name: "slack-token",
		Re:   regexp.MustCompile(`xox[bpras]-[A-Za-z0-9\-]+`),
	},
	{
		Name: "pem-private-key",
		Re:   regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----`),
	},
	{
		// Exclude `[` and `]` from the value class so that already-redacted
		// placeholders like `[REDACTED]` are not re-matched (idempotent scans).
		// Real OAuth/API tokens never contain unencoded `[` or `]`.
		Name: "url-param-token",
		Re:   regexp.MustCompile(`(?i)([?&](?:access_token|token|api[_-]?key|apikey|key|auth)=)[^&\s"'<>\[\]]+`),
	},
}

// BuiltinPatterns returns a copy of the built-in named redaction patterns.
// The returned slice is safe to mutate without affecting the package state.
func BuiltinPatterns() []NamedPattern {
	out := make([]NamedPattern, len(builtinPatterns))
	copy(out, builtinPatterns)
	return out
}

// Redactor applies JSON-key redaction and pattern-based redaction. Custom
// patterns are appended after the built-ins.
type Redactor struct {
	custom []*regexp.Regexp
}

// NewRedactor creates a Redactor with optional extra patterns appended after
// the built-ins.
func NewRedactor(custom []*regexp.Regexp) *Redactor {
	return &Redactor{custom: custom}
}

// Redact removes sensitive data from raw. It applies three passes:
//  1. JSON-aware key redaction (sensitiveKeys).
//  2. Built-in NamedPatterns (BuiltinPatterns). The url-param-token pattern
//     uses a capture-group replacement to preserve the key name.
//  3. Custom patterns supplied at construction time.
func (r *Redactor) Redact(raw string) string {
	// 1. JSON-aware key redaction.
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		redacted := redactValue(parsed)
		if b, err := json.Marshal(redacted); err == nil {
			raw = string(b)
		}
	}

	// 2. Built-in patterns.
	for _, p := range builtinPatterns {
		if p.Name == "url-param-token" {
			// Preserve the key name; replace only the value.
			raw = p.Re.ReplaceAllString(raw, "${1}[REDACTED]")
		} else {
			raw = p.Re.ReplaceAllString(raw, "[REDACTED]")
		}
	}

	// 3. Custom patterns.
	for _, re := range r.custom {
		raw = re.ReplaceAllString(raw, "[REDACTED]")
	}

	return raw
}

// defaultRedactor is used by the package-level Redact shim.
var defaultRedactor = NewRedactor(nil)

// Redact is a package-level shim that calls the default Redactor.
// Callers that need custom patterns should construct a *Redactor via NewRedactor.
func Redact(raw string) string { return defaultRedactor.Redact(raw) }

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

// ScanJSONLeaks returns the JSON paths of values stored under sensitive keys
// whose value is non-empty and not equal to "[REDACTED]". Returns nil if raw is
// not valid JSON. Used by the audit-secrets scanner to detect leaks the JSON-key
// redaction pass should have caught but didn't.
func ScanJSONLeaks(raw string) []string {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil
	}
	var leaks []string
	walkSensitive(v, "", &leaks)
	return leaks
}

func walkSensitive(v any, path string, leaks *[]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			childPath := path + "." + k
			if path == "" {
				childPath = k
			}
			if sensitiveKeys[strings.ToLower(k)] {
				if s, ok := child.(string); ok && s != "" && s != redacted {
					*leaks = append(*leaks, childPath)
				}
				continue // do not recurse into a sensitive subtree
			}
			walkSensitive(child, childPath, leaks)
		}
	case []any:
		for i, child := range val {
			walkSensitive(child, fmt.Sprintf("%s[%d]", path, i), leaks)
		}
	}
}
