package policy

// DefaultRules returns the built-in policy rules.
func DefaultRules() []Rule {
	risk70 := 70
	risk50 := 50
	return []Rule{
		{
			Name:           "block_destructive_ops",
			Description:    "Block delete operations on sensitive tools",
			Enabled:        true,
			ToolPattern:    "delete_*",
			OperationTypes: []string{"delete"},
			MinRiskScore:   &risk70,
			Action:         "block",
		},
		{
			Name:         "pause_high_risk",
			Description:  "Pause high-risk operations for approval",
			Enabled:      true,
			MinRiskScore: &risk50,
			Action:       "pause",
		},
		{
			Name:           "flag_sql_mutations",
			Description:    "Flag SQL write/delete/execute operations",
			Enabled:        true,
			ServerPattern:  "postgres*",
			OperationTypes: []string{"write", "delete", "execute"},
			Action:         "flag",
		},
		{
			Name:        "flag_auth_tools",
			Description: "Flag tools that interact with authentication",
			Enabled:     true,
			ToolPattern: "*auth*",
			Action:      "flag",
		},
		{
			Name:           "flag_config_changes",
			Description:    "Flag configuration modification tools",
			Enabled:        true,
			ToolPattern:    "*config*",
			OperationTypes: []string{"write", "delete"},
			Action:         "flag",
		},
		{
			Name:        "flag_external_messages",
			Description: "Flag tools that send external messages",
			Enabled:     true,
			ToolPattern: "send_*",
			Action:      "flag",
		},
	}
}
