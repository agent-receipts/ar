package taxonomy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func TestClassifyToolCallWithMapping(t *testing.T) {
	mappings := []TaxonomyMapping{
		{ToolName: "read_file", ActionType: "filesystem.file.read"},
		{ToolName: "write_file", ActionType: "filesystem.file.create"},
	}

	result := ClassifyToolCall("read_file", mappings)
	if result.ActionType != "filesystem.file.read" {
		t.Errorf("expected filesystem.file.read, got %s", result.ActionType)
	}
	if result.RiskLevel != receipt.RiskLow {
		t.Errorf("expected low, got %s", result.RiskLevel)
	}
}

func TestClassifyToolCallUnknown(t *testing.T) {
	result := ClassifyToolCall("some_random_tool", nil)
	if result.ActionType != "unknown" {
		t.Errorf("expected unknown, got %s", result.ActionType)
	}
	if result.RiskLevel != receipt.RiskMedium {
		t.Errorf("expected medium, got %s", result.RiskLevel)
	}
}

func TestResolveActionType(t *testing.T) {
	entry := ResolveActionType("filesystem.file.delete")
	if entry.RiskLevel != receipt.RiskHigh {
		t.Errorf("expected high, got %s", entry.RiskLevel)
	}

	entry = ResolveActionType("nonexistent.type")
	if entry.Type != "unknown" {
		t.Errorf("expected unknown fallback, got %s", entry.Type)
	}
}

func TestGetActionType(t *testing.T) {
	entry := GetActionType("system.command.execute")
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.RiskLevel != receipt.RiskHigh {
		t.Errorf("expected high, got %s", entry.RiskLevel)
	}

	if got := GetActionType("does.not.exist"); got != nil {
		t.Errorf("expected nil for unknown type, got %+v", got)
	}
}

func TestAllActions(t *testing.T) {
	all := AllActions()
	// 7 filesystem + 7 system + 3 data + 1 diagnostic + 1 unknown = 19
	if len(all) != 19 {
		t.Errorf("expected 19 action types, got %d", len(all))
	}
}

func TestLoadTaxonomyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "taxonomy.json")

	content := `{"mappings":[{"tool_name":"read_file","action_type":"filesystem.file.read"},{"tool_name":"delete_file","action_type":"filesystem.file.delete"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	mappings, err := LoadTaxonomyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 {
		t.Errorf("expected 2 mappings, got %d", len(mappings))
	}
}

func TestDataActionTypes(t *testing.T) {
	entry := ResolveActionType("data.api.read")
	if entry.RiskLevel != receipt.RiskLow {
		t.Errorf("expected low risk for data.api.read, got %s", entry.RiskLevel)
	}

	entry = ResolveActionType("data.api.write")
	if entry.RiskLevel != receipt.RiskMedium {
		t.Errorf("expected medium risk for data.api.write, got %s", entry.RiskLevel)
	}

	entry = ResolveActionType("data.api.delete")
	if entry.RiskLevel != receipt.RiskHigh {
		t.Errorf("expected high risk for data.api.delete, got %s", entry.RiskLevel)
	}
}

func TestClassifyGitHubTool(t *testing.T) {
	mappings := []TaxonomyMapping{
		{ToolName: "merge_pull_request", ActionType: "data.api.write"},
		{ToolName: "list_issues", ActionType: "data.api.read"},
	}

	result := ClassifyToolCall("merge_pull_request", mappings)
	if result.ActionType != "data.api.write" {
		t.Errorf("expected data.api.write, got %s", result.ActionType)
	}
	if result.RiskLevel != receipt.RiskMedium {
		t.Errorf("expected medium risk, got %s", result.RiskLevel)
	}

	result = ClassifyToolCall("list_issues", mappings)
	if result.ActionType != "data.api.read" {
		t.Errorf("expected data.api.read, got %s", result.ActionType)
	}
	if result.RiskLevel != receipt.RiskLow {
		t.Errorf("expected low risk, got %s", result.RiskLevel)
	}
}

func TestLoadTaxonomyConfigRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "taxonomy.json")

	content := `{"mappings":[{"tool_name":"read_file","action_type":"filesystem.file.read"},{"tool_name":"read_file","action_type":"filesystem.file.modify"}]}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadTaxonomyConfig(path)
	if err == nil {
		t.Error("expected error for duplicate tool_name")
	}
}
