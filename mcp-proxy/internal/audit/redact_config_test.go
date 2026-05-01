package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPatternsValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	if err := os.WriteFile(path, []byte(`
patterns:
  - name: my-secret
    pattern: 'MY_SECRET_[A-Z0-9]+'
  - name: internal-id
    pattern: 'INT-[0-9]+'
`), 0600); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadPatterns(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(patterns))
	}
	if patterns[0].Name != "my-secret" {
		t.Errorf("expected name %q, got %q", "my-secret", patterns[0].Name)
	}
	if patterns[1].Name != "internal-id" {
		t.Errorf("expected name %q, got %q", "internal-id", patterns[1].Name)
	}
	// Patterns must compile and match.
	if !patterns[0].Re.MatchString("MY_SECRET_ABC123") {
		t.Error("pattern my-secret did not match expected input")
	}
	if !patterns[1].Re.MatchString("INT-42") {
		t.Error("pattern internal-id did not match expected input")
	}
}

func TestLoadPatternsMissingName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	if err := os.WriteFile(path, []byte(`
patterns:
  - name: ok
    pattern: 'OK-[0-9]+'
  - pattern: 'NO_NAME_[A-Z]+'
`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadPatterns(path)
	if err == nil {
		t.Fatal("expected error for missing name, got nil")
	}
}

func TestLoadPatternsInvalidRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	if err := os.WriteFile(path, []byte(`
patterns:
  - name: bad-regex
    pattern: '['
`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadPatterns(path)
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestLoadPatternsMissingFile(t *testing.T) {
	_, err := LoadPatterns("/nonexistent/path/patterns.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadPatternsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(``), 0600); err != nil {
		t.Fatal(err)
	}

	patterns, err := LoadPatterns(path)
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	if len(patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(patterns))
	}
}

func TestLoadPatternsEmptyPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	if err := os.WriteFile(path, []byte(`
patterns:
  - name: empty-pattern
    pattern: ""
`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadPatterns(path)
	if err == nil {
		t.Fatal("expected error for empty pattern, got nil")
	}
	if !strings.Contains(err.Error(), "pattern is required") {
		t.Errorf("expected error to mention 'pattern is required', got: %v", err)
	}
}

func TestLoadPatternsWhitespacePattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	if err := os.WriteFile(path, []byte(`
patterns:
  - name: whitespace-pattern
    pattern: "   "
`), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadPatterns(path)
	if err == nil {
		t.Fatal("expected error for whitespace-only pattern, got nil")
	}
	if !strings.Contains(err.Error(), "pattern is required") {
		t.Errorf("expected error to mention 'pattern is required', got: %v", err)
	}
}
