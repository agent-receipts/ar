package configs

import (
	"testing"
)

func TestBundledTaxonomiesIncludesGitHubAndAtlassian(t *testing.T) {
	mappings, err := BundledTaxonomies()
	if err != nil {
		t.Fatalf("BundledTaxonomies: %v", err)
	}
	if len(mappings) == 0 {
		t.Fatal("expected bundled mappings, got none")
	}

	want := map[string]string{
		// GitHub MCP
		"create_pull_request": "data.api.write",
		"merge_pull_request":  "data.api.write",
		"list_issues":         "data.api.read",
		// Atlassian MCP
		"createJiraIssue":          "data.api.write",
		"editJiraIssue":            "data.api.write",
		"searchJiraIssuesUsingJql": "data.api.read",
		"createConfluencePage":     "data.api.write",
	}
	got := make(map[string]string, len(mappings))
	for _, m := range mappings {
		got[m.ToolName] = m.ActionType
	}
	for tool, action := range want {
		if got[tool] != action {
			t.Errorf("mapping for %q: want %q, got %q", tool, action, got[tool])
		}
	}
}

func TestBundledNames(t *testing.T) {
	names := BundledNames()
	want := map[string]bool{"github": false, "atlassian": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("expected bundled name %q, not present in %v", n, names)
		}
	}
}
