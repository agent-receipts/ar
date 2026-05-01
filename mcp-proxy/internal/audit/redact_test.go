package audit

import (
	"regexp"
	"strings"
	"testing"
)

func TestRedactSensitiveKeys(t *testing.T) {
	input := `{"username":"alice","password":"s3cret","data":"safe"}`
	got := Redact(input)
	if strings.Contains(got, "s3cret") {
		t.Error("password not redacted")
	}
	if !strings.Contains(got, "alice") {
		t.Error("username should not be redacted")
	}
	if !strings.Contains(got, "safe") {
		t.Error("data should not be redacted")
	}
}

func TestRedactPatterns(t *testing.T) {
	input := `token: ghp_1234567890123456789012345678901234567`
	got := Redact(input)
	if strings.Contains(got, "ghp_") {
		t.Error("GitHub PAT not redacted")
	}
}

func TestRedactNestedJSON(t *testing.T) {
	input := `{"config":{"api_key":"abc123","host":"example.com"}}`
	got := Redact(input)
	if strings.Contains(got, "abc123") {
		t.Error("nested api_key not redacted")
	}
	if !strings.Contains(got, "example.com") {
		t.Error("host should not be redacted")
	}
}

func TestRedactNonJSON(t *testing.T) {
	input := "plain text with no json"
	got := Redact(input)
	if got != input {
		t.Errorf("expected unchanged string, got %q", got)
	}
}

func TestRedactDeeplyNested(t *testing.T) {
	input := `{"a":{"b":{"c":{"secret":"val"}}}}`
	got := Redact(input)
	if strings.Contains(got, "val") {
		t.Error("deeply nested secret not redacted")
	}
}

func TestRedactPEMBlock(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALR1234567890\nabcdefghijklmnop\n-----END RSA PRIVATE KEY-----"
	input := `some text ` + pem + ` more text`
	got := Redact(input)
	if strings.Contains(got, "MIIBog") {
		t.Error("PEM key body not redacted")
	}
	if strings.Contains(got, "BEGIN RSA PRIVATE KEY") {
		t.Error("PEM header not redacted")
	}
	if !strings.Contains(got, "some text") {
		t.Error("surrounding text should be preserved")
	}
}

func TestRedactTokenFormats(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{
			name: "github-pat-classic",
			in:   "ghp_" + strings.Repeat("a", 36),
		},
		{
			name: "github-pat-finegrained",
			in:   "github_pat_" + strings.Repeat("a", 82),
		},
		{
			name: "github-oauth",
			in:   "gho_" + strings.Repeat("a", 36),
		},
		{
			name: "github-app-installation",
			in:   "ghs_" + strings.Repeat("a", 36),
		},
		{
			name: "github-user-to-server",
			in:   "ghu_" + strings.Repeat("a", 36),
		},
		{
			name: "github-installation-legacy",
			in:   "v1." + strings.Repeat("a", 40),
		},
		{
			name: "openai-anthropic-key",
			in:   "sk-" + strings.Repeat("a", 20),
		},
		{
			name: "aws-access-key",
			in:   "AKIA" + strings.Repeat("A", 16),
		},
		{
			name: "bearer-token",
			in:   "Bearer " + strings.Repeat("a", 20),
		},
		{
			name: "slack-token",
			in:   "xoxb-abc123-def456",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := Redact(tc.in)
			if strings.Contains(out, tc.in) {
				t.Errorf("token not redacted: output %q still contains full input token", out)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("expected [REDACTED] in output, got %q", out)
			}
		})
	}
}

// TestRedactLegacyVersionNotRedacted verifies that semver strings like "v1.0.0"
// are not matched by the github-installation-legacy pattern, which requires 40+
// lowercase hex chars after "v1.".
func TestRedactLegacyVersionNotRedacted(t *testing.T) {
	input := "v1.0.0"
	got := Redact(input)
	if got != input {
		t.Errorf("semver v1.0.0 should not be redacted, got %q", got)
	}
}

func TestRedactLocations(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)

	t.Run("header-style", func(t *testing.T) {
		in := "Authorization: Bearer " + token
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted in header: %q", out)
		}
	})

	t.Run("url-param-GET", func(t *testing.T) {
		in := "GET /repos?token=" + token + " HTTP/1.1"
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted in URL param: %q", out)
		}
		if !strings.Contains(out, "token=") {
			t.Errorf("key name 'token=' should be preserved: %q", out)
		}
	})

	t.Run("url-param-access_token", func(t *testing.T) {
		in := "https://api.example.com/x?access_token=" + token
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted in access_token: %q", out)
		}
		if !strings.Contains(out, "access_token=") {
			t.Errorf("key 'access_token=' should be preserved: %q", out)
		}
	})

	t.Run("json-nested-sensitive-key", func(t *testing.T) {
		in := `{"auth":{"token":"` + token + `"}}`
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted under sensitive JSON key: %q", out)
		}
	})

	t.Run("json-nested-non-sensitive-key", func(t *testing.T) {
		in := `{"data":{"note":"my key is ` + token + `"}}`
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted via regex under non-sensitive key: %q", out)
		}
	})

	t.Run("plain-error-string", func(t *testing.T) {
		in := "request failed with token " + token
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted in plain error string: %q", out)
		}
	})
}

func TestRedactorCustomPatterns(t *testing.T) {
	re := regexp.MustCompile(`SECRET-[A-Z0-9]+`)
	r := NewRedactor([]*regexp.Regexp{re})
	out := r.Redact("here is SECRET-ABC123 in text")
	if strings.Contains(out, "SECRET-ABC123") {
		t.Errorf("custom pattern not applied: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got %q", out)
	}
}

func TestRedactorURLParamPreservesKey(t *testing.T) {
	token := "ghp_" + strings.Repeat("a", 36)
	out := Redact("?token=" + token + "&other=keep")
	if strings.Contains(out, token) {
		t.Errorf("token value not redacted: %q", out)
	}
	if !strings.Contains(out, "token=") {
		t.Errorf("key 'token=' should be preserved: %q", out)
	}
	if !strings.Contains(out, "other=keep") {
		t.Errorf("unrelated param 'other=keep' should be preserved: %q", out)
	}
}

func TestRedactURLParamCaseInsensitive(t *testing.T) {
	token := "ghp_" + strings.Repeat("z", 36)

	t.Run("mixed-case-Token", func(t *testing.T) {
		in := "https://api.example.com/x?Token=" + token
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted in mixed-case param: %q", out)
		}
		if !strings.Contains(out, "Token=") {
			t.Errorf("key 'Token=' should be preserved: %q", out)
		}
	})

	t.Run("upper-case-API_KEY", func(t *testing.T) {
		in := "https://api.example.com/x?API_KEY=" + token
		out := Redact(in)
		if strings.Contains(out, token) {
			t.Errorf("token not redacted in upper-case API_KEY param: %q", out)
		}
		if !strings.Contains(out, "API_KEY=") {
			t.Errorf("key 'API_KEY=' should be preserved: %q", out)
		}
	})
}

// TestRedactURLParamSkipsAlreadyRedacted verifies that an already-redacted URL
// parameter is not double-redacted, and that the scanner (BuiltinPatterns) does
// not flag it as a hit.
func TestRedactURLParamSkipsAlreadyRedacted(t *testing.T) {
	input := "?token=[REDACTED]&other=keep"

	// Redactor must leave the placeholder untouched.
	out := Redact(input)
	if out != input {
		t.Errorf("Redact mutated already-redacted placeholder: got %q, want %q", out, input)
	}

	// Scanner (BuiltinPatterns) must not flag the already-redacted value.
	patterns := BuiltinPatterns()
	for _, p := range patterns {
		if p.Name != "url-param-token" {
			continue
		}
		if p.Re.MatchString(input) {
			t.Errorf("url-param-token scanner regex incorrectly matches already-redacted input %q", input)
		}
	}
}

func TestScanJSONLeaks(t *testing.T) {
	t.Run("non-json returns nil", func(t *testing.T) {
		got := ScanJSONLeaks("not json at all")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("clean json returns empty", func(t *testing.T) {
		got := ScanJSONLeaks(`{"username":"alice","data":"safe"}`)
		if len(got) != 0 {
			t.Errorf("expected no leaks, got %v", got)
		}
	})

	t.Run("password hunter2 detected", func(t *testing.T) {
		got := ScanJSONLeaks(`{"password":"hunter2"}`)
		if len(got) != 1 || got[0] != "password" {
			t.Errorf("expected [password], got %v", got)
		}
	})

	t.Run("nested token detected", func(t *testing.T) {
		got := ScanJSONLeaks(`{"a":{"token":"x"}}`)
		if len(got) != 1 || got[0] != "a.token" {
			t.Errorf("expected [a.token], got %v", got)
		}
	})

	t.Run("already redacted not reported", func(t *testing.T) {
		got := ScanJSONLeaks(`{"password":"[REDACTED]"}`)
		if len(got) != 0 {
			t.Errorf("expected no leaks for already-redacted, got %v", got)
		}
	})

	t.Run("sensitive key with non-string value", func(t *testing.T) {
		got := ScanJSONLeaks(`{"password":null}`)
		if len(got) != 0 {
			t.Errorf("expected no leaks for null value, got %v", got)
		}
	})
}
