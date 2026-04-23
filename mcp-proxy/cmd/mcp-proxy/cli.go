package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

func openReceiptStore(path string) *store.Store {
	if err := ensureDBDir(path); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating receipt store directory: %v\n", err)
		os.Exit(1)
	}
	s, err := store.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening receipt store: %v\n", err)
		os.Exit(1)
	}
	return s
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	db := fs.String("receipt-db", defaultDBPath("receipts.db"), "Receipt store path")
	chainID := fs.String("chain", "", "Filter by chain ID")
	riskLevel := fs.String("risk", "", "Filter by risk level")
	actionType := fs.String("action", "", "Filter by action type")
	asJSON := fs.Bool("json", false, "Output as JSON")
	limit := fs.Int("limit", 50, "Max results")
	fs.Parse(args)

	s := openReceiptStore(*db)
	defer s.Close()

	q := store.Query{Limit: limit, NewestFirst: true}
	if *chainID != "" {
		q.ChainID = chainID
	}
	if *riskLevel != "" {
		rl := receipt.RiskLevel(*riskLevel)
		q.RiskLevel = &rl
	}
	if *actionType != "" {
		q.ActionType = actionType
	}

	receipts, err := s.QueryReceipts(q)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying receipts: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(receipts)
		return
	}

	const rowFmt = "%-40s %-22s %-6s %-8s %-14s %-22s %s\n"
	fmt.Printf(rowFmt, "ID", "ACTION", "RISK", "STATUS", "ISSUER", "OPERATOR", "TIMESTAMP")
	fmt.Println("---")
	for _, r := range receipts {
		subj := r.CredentialSubject
		operator := ""
		if r.Issuer.Operator != nil {
			operator = r.Issuer.Operator.ID
		}
		fmt.Printf(rowFmt,
			truncate(r.ID, 40),
			truncate(subj.Action.Type, 22),
			subj.Action.RiskLevel,
			subj.Outcome.Status,
			truncate(r.Issuer.Name, 14),
			truncate(operator, 22),
			subj.Action.Timestamp,
		)
	}
	fmt.Printf("\n%d receipts\n", len(receipts))
}

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	db := fs.String("receipt-db", defaultDBPath("receipts.db"), "Receipt store path")
	pubKeyPath := fs.String("key", "", "Public key (PEM file) for signature verification")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: mcp-proxy inspect <receipt-id>")
		os.Exit(1)
	}
	id := fs.Arg(0)

	s := openReceiptStore(*db)
	defer s.Close()

	r, err := s.GetByID(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if r == nil {
		fmt.Fprintf(os.Stderr, "Receipt not found: %s\n", id)
		os.Exit(1)
	}

	subj := r.CredentialSubject
	fmt.Printf("Receipt:    %s\n", r.ID)
	fmt.Printf("Issuer:     %s\n", r.Issuer.ID)
	fmt.Printf("Principal:  %s\n", subj.Principal.ID)
	fmt.Printf("Action:     %s\n", subj.Action.Type)
	fmt.Printf("Risk:       %s\n", subj.Action.RiskLevel)
	fmt.Printf("Status:     %s\n", subj.Outcome.Status)
	fmt.Printf("Chain:      %s (seq %d)\n", subj.Chain.ChainID, subj.Chain.Sequence)
	fmt.Printf("Timestamp:  %s\n", subj.Action.Timestamp)
	fmt.Printf("Issued:     %s\n", r.IssuanceDate)

	if *pubKeyPath != "" {
		pubPEM, err := os.ReadFile(*pubKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read public key: %v\n", err)
			os.Exit(1)
		}
		valid, err := receipt.Verify(*r, string(pubPEM))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verify: %v\n", err)
			os.Exit(1)
		}
		if valid {
			fmt.Println("Signature:  VALID")
		} else {
			fmt.Println("Signature:  INVALID")
		}
	}
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	db := fs.String("receipt-db", defaultDBPath("receipts.db"), "Receipt store path")
	pubKeyPath := fs.String("key", "", "Public key (PEM file) — required")
	fs.Parse(args)

	if fs.NArg() < 1 || *pubKeyPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: mcp-proxy verify --key <pubkey.pem> <chain-id>")
		os.Exit(1)
	}
	chainID := fs.Arg(0)

	pubPEM, err := os.ReadFile(*pubKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read public key: %v\n", err)
		os.Exit(1)
	}

	s := openReceiptStore(*db)
	defer s.Close()

	result, err := s.VerifyStoredChain(chainID, string(pubPEM))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if result.ResponseHashNote != "" {
		fmt.Fprintf(os.Stderr, "Note: %s\n", result.ResponseHashNote)
	}

	if result.Valid {
		fmt.Printf("Chain %s: VALID (%d receipts)\n", chainID, result.Length)
	} else {
		fmt.Printf("Chain %s: BROKEN at receipt %d\n", chainID, result.BrokenAt)
		for _, rv := range result.Receipts {
			status := "ok"
			if !rv.SignatureValid {
				status = "BAD SIGNATURE"
			} else if !rv.HashLinkValid {
				status = "BAD HASH LINK"
			} else if !rv.SequenceValid {
				status = "BAD SEQUENCE"
			}
			fmt.Printf("  [%d] %s — %s\n", rv.Index, rv.ReceiptID, status)
		}
		os.Exit(1)
	}
}

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	db := fs.String("receipt-db", defaultDBPath("receipts.db"), "Receipt store path")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: mcp-proxy export <chain-id>")
		os.Exit(1)
	}
	chainID := fs.Arg(0)

	s := openReceiptStore(*db)
	defer s.Close()

	receipts, err := s.GetChain(chainID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	export := map[string]any{
		"chainId":    chainID,
		"exportedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"count":      len(receipts),
		"receipts":   receipts,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(export)
}

func cmdStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	db := fs.String("receipt-db", defaultDBPath("receipts.db"), "Receipt store path")
	asJSON := fs.Bool("json", false, "Output as JSON")
	fs.Parse(args)

	s := openReceiptStore(*db)
	defer s.Close()

	st, err := s.Stats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(st)
		return
	}

	fmt.Printf("Total receipts: %d\n", st.Total)
	fmt.Printf("Chains:         %d\n", st.Chains)
	if len(st.ByRisk) > 0 {
		fmt.Println("\nBy risk level:")
		for _, g := range st.ByRisk {
			fmt.Printf("  %-10s %d\n", g.Label, g.Count)
		}
	}
	if len(st.ByStatus) > 0 {
		fmt.Println("\nBy status:")
		for _, g := range st.ByStatus {
			fmt.Printf("  %-10s %d\n", g.Label, g.Count)
		}
	}
	if len(st.ByAction) > 0 {
		fmt.Println("\nBy action type:")
		for _, g := range st.ByAction {
			fmt.Printf("  %-30s %d\n", g.Label, g.Count)
		}
	}
}

func openAuditStore(path string) *audit.Store {
	if err := ensureDBDir(path); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating audit store directory: %v\n", err)
		os.Exit(1)
	}
	s, err := audit.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening audit store: %v\n", err)
		os.Exit(1)
	}
	return s
}

func cmdTiming(args []string) {
	fs := flag.NewFlagSet("timing", flag.ExitOnError)
	db := fs.String("db", defaultDBPath("audit.db"), "Audit database path")
	session := fs.String("session", "", "Filter by session ID")
	asJSON := fs.Bool("json", false, "Output as JSON")
	limit := fs.Int("limit", 20, "Max tools to show")
	fs.Parse(args)

	s := openAuditStore(*db)
	defer s.Close()

	st, err := s.TimingStats(*session, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(st)
		return
	}

	fmt.Printf("Tool call timing (%d calls)\n", st.Total)

	if len(st.ByTool) > 0 {
		fmt.Println("\nPer-tool averages:")
		fmt.Printf("%-30s %6s %12s %10s %11s %13s %10s\n", "TOOL", "COUNT", "UPSTREAM(us)", "POLICY(us)", "RECEIPT(us)", "APPROVAL(us)", "TOTAL(ms)")
		for _, tt := range st.ByTool {
			fmt.Printf("%-30s %6d %12s %10s %11s %13s %10s\n",
				truncate(tt.ToolName, 30),
				tt.Count,
				fmtOptInt(tt.AvgUpstreamUs),
				fmtOptInt(tt.AvgPolicyUs),
				fmtOptInt(tt.AvgReceiptUs),
				fmtOptInt(tt.AvgApprovalUs),
				fmtOptInt(tt.AvgDurationMs),
			)
		}
	}

	if len(st.Percentiles) > 0 {
		fmt.Println("\nPercentiles:")
		fmt.Printf("%-15s %10s %10s %10s\n", "PHASE", "p50", "p95", "p99")
		for _, name := range []string{"upstream", "policy_eval", "receipt_sign", "duration_ms"} {
			if p, ok := st.Percentiles[name]; ok {
				unit := "(us)"
				if name == "duration_ms" {
					unit = "(ms)"
				}
				fmt.Printf("%-15s %10d %10d %10d %s\n", name, p.P50, p.P95, p.P99, unit)
			}
		}
	}

	if len(st.PolicyActions) > 0 {
		fmt.Println("\nPolicy actions:")
		fmt.Printf("%-30s %6s %6s %6s %6s %10s\n", "TOOL", "PASS", "FLAG", "PAUSE", "BLOCK", "REJECTED")
		for _, pa := range st.PolicyActions {
			fmt.Printf("%-30s %6d %6d %6d %6d %10d\n",
				truncate(pa.ToolName, 30),
				pa.Pass, pa.Flag, pa.Pause, pa.Block, pa.Rejected,
			)
		}
	}
}

// DoctorReport is the structured output of `mcp-proxy doctor`. Exposed for
// test-only consumers; the CLI renders it to text or JSON.
type DoctorReport struct {
	RulesPath      string   `json:"rules_path"`
	TotalRules     int      `json:"total_rules"`
	EnabledRules   int      `json:"enabled_rules"`
	PauseRules     []string `json:"pause_rules"`
	BlockRules     []string `json:"block_rules"`
	FlagRules      []string `json:"flag_rules"`
	DisabledRules  []string `json:"disabled_rules,omitempty"`
	ApproverURL    string   `json:"approver_url"`
	ApproverReach  string   `json:"approver_reachable"` // reachable | unreachable | not_configured
	ApproverDetail string   `json:"approver_detail,omitempty"`
	Issues         []string `json:"issues"`
	Healthy        bool     `json:"healthy"`
}

// DiagnoseConfig builds a DoctorReport from a rules path and approver URL.
// Pure function — no I/O beyond reading the rules file and probing the URL.
// Returns the report and an overall exit-code bool (true = healthy).
func DiagnoseConfig(rulesPath, approverURL string, probe func(url string) (string, error)) (DoctorReport, bool) {
	report := DoctorReport{
		RulesPath:   rulesPath,
		ApproverURL: approverURL,
	}

	var rules []policy.Rule
	var err error
	if rulesPath == "" {
		rules = policy.DefaultRules()
		report.RulesPath = "(built-in defaults)"
	} else {
		rules, err = policy.LoadRules(rulesPath)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("load rules: %v", err))
			return report, false
		}
	}
	engine := policy.NewEngine(rules)
	summary := engine.Describe()
	report.TotalRules = summary.TotalRules
	report.EnabledRules = summary.EnabledRules
	report.PauseRules = summary.PauseRules
	report.BlockRules = summary.BlockRules
	report.FlagRules = summary.FlagRules
	report.DisabledRules = summary.DisabledRules

	switch {
	case approverURL == "":
		report.ApproverReach = "not_configured"
		if summary.NeedsApprover() {
			report.Issues = append(report.Issues,
				fmt.Sprintf("%d pause rule(s) loaded but no approver URL configured — pause calls will fail with -32003", len(summary.PauseRules)))
		}
	default:
		detail, perr := probe(approverURL)
		if perr == nil {
			report.ApproverReach = "reachable"
			report.ApproverDetail = detail
		} else {
			report.ApproverReach = "unreachable"
			report.ApproverDetail = perr.Error()
			report.Issues = append(report.Issues, fmt.Sprintf("approver at %s is unreachable: %v", approverURL, perr))
		}
	}

	report.Healthy = len(report.Issues) == 0
	return report, report.Healthy
}

// probeApprover makes a lightweight HEAD/GET against the approver URL to
// check it's alive. It accepts any HTTP response — including 401/404 —
// because the goal is reachability, not endpoint correctness. Only
// connection-level failures (DNS, refused, TLS) are treated as unreachable.
func probeApprover(url string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return fmt.Sprintf("HTTP %d", resp.StatusCode), nil
}

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "Policy rules YAML (default: built-in)")
	approverURL := fs.String("approver", "", "Approver URL to probe (default: none)")
	asJSON := fs.Bool("json", false, "Output as JSON")
	fs.Parse(args)

	report, healthy := DiagnoseConfig(*rulesPath, *approverURL, probeApprover)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		if !healthy {
			os.Exit(1)
		}
		return
	}

	fmt.Printf("mcp-proxy doctor\n")
	fmt.Printf("  rules:         %s\n", report.RulesPath)
	fmt.Printf("  loaded:        %d enabled (%d total)\n", report.EnabledRules, report.TotalRules)
	if len(report.PauseRules) > 0 {
		fmt.Printf("  pause rules:   %s\n", strings.Join(report.PauseRules, ", "))
	}
	if len(report.BlockRules) > 0 {
		fmt.Printf("  block rules:   %s\n", strings.Join(report.BlockRules, ", "))
	}
	if len(report.FlagRules) > 0 {
		fmt.Printf("  flag rules:    %s\n", strings.Join(report.FlagRules, ", "))
	}
	fmt.Printf("  approver:      %s", report.ApproverReach)
	if report.ApproverURL != "" {
		fmt.Printf(" (%s)", report.ApproverURL)
	}
	if report.ApproverDetail != "" {
		fmt.Printf(" — %s", report.ApproverDetail)
	}
	fmt.Println()

	if len(report.Issues) == 0 {
		fmt.Println("\nOK — configuration is healthy.")
		return
	}

	fmt.Println("\nIssues:")
	for _, issue := range report.Issues {
		fmt.Printf("  - %s\n", issue)
	}
	os.Exit(1)
}

func fmtOptInt(v *int64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *v)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
