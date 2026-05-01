package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
	"github.com/agent-receipts/ar/mcp-proxy/internal/policy"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

const listRowFmt = "%-22s %-14s %-30s %-22s %-8s %-8s %s\n"

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
	follow := fs.Bool("follow", false, "Stream new rows as they are inserted (tail -f)")
	fs.BoolVar(follow, "f", false, "Alias for -follow")
	interval := fs.Duration("interval", 500*time.Millisecond, "Poll interval for --follow mode")
	fs.Parse(args)

	if err := validateFollowFlags(*follow, *interval); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

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

	// Set up the signal context up front in follow mode so Ctrl-C can
	// interrupt the startup watermark query too (the DB may be busy/locked).
	var (
		ctx  context.Context
		stop context.CancelFunc
	)
	if *follow {
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
	}

	// In follow mode we capture the watermark atomically with the initial
	// query so a row inserted between the two can't be silently skipped.
	var (
		receipts   []receipt.AgentReceipt
		startRowID int64
		err        error
	)
	if *follow {
		receipts, startRowID, err = s.QueryReceiptsWithWatermarkContext(ctx, q)
	} else {
		receipts, err = s.QueryReceipts(q)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying receipts: %v\n", err)
		os.Exit(1)
	}

	// In follow mode the streamed rows are chronological (oldest → newest)
	// via rowid ASC. Flip the initial batch so the overall output reads in
	// one consistent direction and feels tail-like.
	if *follow {
		reverseReceipts(receipts)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		if *follow {
			// NDJSON — stream-compatible with the follow loop's output.
			for _, r := range receipts {
				if err := enc.Encode(r); err != nil {
					fmt.Fprintf(os.Stderr, "Error encoding receipt: %v\n", err)
					os.Exit(1)
				}
			}
		} else {
			enc.SetIndent("", "  ")
			if err := enc.Encode(receipts); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding receipts: %v\n", err)
				os.Exit(1)
			}
		}
	} else {
		fmt.Printf(listRowFmt, "ID", "SERVER", "TOOL", "ACTION", "RISK", "STATUS", "TIMESTAMP")
		fmt.Println("---")
		writeReceiptRows(os.Stdout, receipts)
		if !*follow {
			fmt.Printf("\n%d receipts\n", len(receipts))
		}
	}

	if !*follow {
		return
	}

	// Follow mode strips NewestFirst/Limit: we want all new rows in insertion
	// order as they arrive.
	followQ := q
	followQ.NewestFirst = false
	followQ.Limit = nil

	if err := runFollowLoop(ctx, s, startRowID, followQ, *interval, *asJSON, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Error in follow loop: %v\n", err)
		os.Exit(1)
	}
}

// validateFollowFlags returns an error when --follow is set with a
// non-positive --interval. Pulled out of cmdList so it can be tested
// without invoking os.Exit.
func validateFollowFlags(follow bool, interval time.Duration) error {
	if follow && interval <= 0 {
		return fmt.Errorf("--interval must be positive, got %s", interval)
	}
	return nil
}

// runFollowLoop polls the store on every tick for rows past lastRowID and
// writes them to w. Exits cleanly when ctx is canceled (e.g. Ctrl-C).
func runFollowLoop(ctx context.Context, s *store.Store, lastRowID int64, q store.Query, interval time.Duration, asJSON bool, w io.Writer) error {
	if interval <= 0 {
		return fmt.Errorf("run follow loop: interval must be positive, got %s", interval)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// One encoder per invocation: reused across ticks to avoid per-poll
	// allocations and to keep encoding configuration in one place.
	var enc *json.Encoder
	if asJSON {
		enc = json.NewEncoder(w)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			newRows, maxRowID, err := s.QueryAfterRowIDContext(ctx, q, lastRowID)
			if err != nil {
				// Treat cancellation as a clean exit, not an error.
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			lastRowID = maxRowID
			if len(newRows) == 0 {
				continue
			}
			if asJSON {
				for _, r := range newRows {
					if err := enc.Encode(r); err != nil {
						return err
					}
				}
			} else {
				writeReceiptRows(w, newRows)
			}
		}
	}
}

// reverseReceipts reverses s in place. Used in follow mode so the initial
// newest-first batch is flipped to chronological order, matching the
// subsequent streamed rows.
func reverseReceipts(s []receipt.AgentReceipt) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func writeReceiptRows(w io.Writer, receipts []receipt.AgentReceipt) {
	for _, r := range receipts {
		subj := r.CredentialSubject
		server := ""
		if subj.Action.Target != nil {
			server = subj.Action.Target.System
		}
		fmt.Fprintf(w, listRowFmt,
			truncate(r.ID, 23),
			truncate(server, 14),
			truncate(subj.Action.ToolName, 30),
			truncate(subj.Action.Type, 22),
			subj.Action.RiskLevel,
			subj.Outcome.Status,
			subj.Action.Timestamp,
		)
	}
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

	if st.Total == st.TimedTotal {
		fmt.Printf("Tool call timing (%d calls)\n", st.Total)
	} else {
		fmt.Printf("Tool call timing (%d calls, %d with duration)\n", st.Total, st.TimedTotal)
	}

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
// Side effects are bounded: it may read the rules file from disk, and calls
// the injected probe (which may perform network I/O). The probe function is
// pluggable so tests can stub it out.
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

// probeApprover makes a lightweight HEAD against the approver URL to check
// it's alive, falling back to GET if the server rejects HEAD. Any HTTP
// response — including 401/404 — counts as reachable; the goal is liveness,
// not endpoint correctness. Only connection-level failures (DNS, refused,
// TLS) are treated as unreachable. Side effects on target servers are
// minimised by trying HEAD first.
func probeApprover(url string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	target := url + "/"

	req, err := http.NewRequest(http.MethodHead, target, nil)
	if err != nil {
		return "", fmt.Errorf("build HEAD request: %w", err)
	}
	resp, headErr := client.Do(req)
	if headErr == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotImplemented {
			return fmt.Sprintf("HTTP %d", resp.StatusCode), nil
		}
	}

	// HEAD failed or server didn't support it — fall back to GET.
	getResp, getErr := client.Get(target)
	if getErr != nil {
		if headErr != nil {
			return "", fmt.Errorf("HEAD: %v; GET: %w", headErr, getErr)
		}
		return "", getErr
	}
	defer getResp.Body.Close()
	return fmt.Sprintf("HTTP %d", getResp.StatusCode), nil
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

// writePrivateKeyFile writes data to path with 0600 permissions. When force is
// false the call fails atomically if the file already exists (O_EXCL). When
// force is true the key is written to a temp file first then renamed into place
// so the previous key remains intact if the write fails.
func writePrivateKeyFile(path string, data []byte, force bool) error {
	if force {
		// Write-then-rename: old key survives intact until the new one is safely on disk.
		dir := filepath.Dir(path)
		tmp, err := os.CreateTemp(dir, ".key-*.tmp")
		if err != nil {
			return fmt.Errorf("create temp key file in %q: %w", dir, err)
		}
		tmpName := tmp.Name()
		if _, werr := tmp.Write(data); werr != nil {
			cerr := tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("write temp key file: %w", errors.Join(werr, cerr))
		}
		if cerr := tmp.Close(); cerr != nil {
			os.Remove(tmpName)
			return fmt.Errorf("close temp key file: %w", cerr)
		}
		// Explicit chmod guarantees 0600 regardless of process umask.
		if chErr := os.Chmod(tmpName, 0o600); chErr != nil {
			os.Remove(tmpName)
			return fmt.Errorf("set permissions on key file %q: %w", path, chErr)
		}
		if rerr := os.Rename(tmpName, path); rerr != nil {
			os.Remove(tmpName)
			return fmt.Errorf("rename key file to %q: %w", path, rerr)
		}
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("key file %q already exists (use -force to overwrite)", path)
		}
		return fmt.Errorf("create key file %q: %w", path, err)
	}
	if _, werr := f.Write(data); werr != nil {
		cerr := f.Close()
		os.Remove(path)
		return fmt.Errorf("write key file %q: %w", path, errors.Join(werr, cerr))
	}
	if cerr := f.Close(); cerr != nil {
		os.Remove(path)
		return fmt.Errorf("close key file %q: %w", path, cerr)
	}
	// Explicit chmod guarantees 0600 regardless of process umask.
	if chErr := os.Chmod(path, 0o600); chErr != nil {
		os.Remove(path)
		return fmt.Errorf("set permissions on key file %q: %w", path, chErr)
	}
	return nil
}

// writePubKeyFile writes data to path with 0644 permissions. When force is false
// the call fails if the file already exists. When force is true the existing file
// is removed first so a fresh inode is created with the correct 0644 mode.
func writePubKeyFile(path string, data []byte, force bool) error {
	if force {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove existing public key %q: %w", path, err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("public key file %q already exists (use -force to overwrite)", path)
		}
		return fmt.Errorf("create public key file %q: %w", path, err)
	}
	if _, werr := f.Write(data); werr != nil {
		cerr := f.Close()
		os.Remove(path)
		return fmt.Errorf("write public key file %q: %w", path, errors.Join(werr, cerr))
	}
	if cerr := f.Close(); cerr != nil {
		os.Remove(path)
		return fmt.Errorf("close public key file %q: %w", path, cerr)
	}
	// Explicit chmod guarantees 0644 regardless of process umask.
	if chErr := os.Chmod(path, 0o644); chErr != nil {
		os.Remove(path)
		return fmt.Errorf("set permissions on public key file %q: %w", path, chErr)
	}
	return nil
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	name := fs.String("name", "default", "Name for this proxy instance (used in filenames and config snippet)")
	noApproval := fs.Bool("no-approval", false, "Omit -http from the config snippet (no approval server)")
	httpPort := fs.Int("http-port", 7778, "Approval listener port written into the config snippet")
	force := fs.Bool("force", false, "Overwrite existing key files")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mcp-proxy init [-name <name>] [-force] [-no-approval] [-http-port <port>]\n\n")
		fmt.Fprintf(os.Stderr, "  One-command setup: creates ~/.agent-receipts/, generates an Ed25519\n")
		fmt.Fprintf(os.Stderr, "  signing keypair with correct permissions, initialises the receipt\n")
		fmt.Fprintf(os.Stderr, "  database, and prints a claude_desktop_config.json snippet to stdout.\n\n")
		fmt.Fprintf(os.Stderr, "  Safe to re-run: warns and skips key generation if files already exist.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if !validInitName(*name) {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: -name %q is invalid: use only letters, digits, hyphens, underscores, and dots (max 64 chars)\n", *name)
		os.Exit(2)
	}
	if *httpPort < 1 || *httpPort > 65535 {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: -http-port %d is out of range (1-65535)\n", *httpPort)
		os.Exit(2)
	}

	home, err := userHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: resolve home directory: %v\n", err)
		os.Exit(1)
	}

	binPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: warning: could not resolve binary path (%v); using %q — replace with an absolute path before saving the snippet\n", err, "mcp-proxy")
		binPath = "mcp-proxy"
	}

	dir := filepath.Join(home, ".agent-receipts")
	if err := runInit(dir, *name, *force, *noApproval, *httpPort, binPath, os.Stderr, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-proxy init: %v\n", err)
		os.Exit(1)
	}
}

// validInitName reports whether name is safe to use as a key filename component.
// Allows letters, digits, hyphens, underscores, and dots; max 64 chars.
// Rejects empty strings and names that would escape the target directory.
func validInitName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// runInit performs the guided setup: creates dir, generates a keypair (idempotent),
// initialises the receipt DB, and writes a config snippet to out. Status messages
// go to errOut. Accepting dir and binPath as parameters makes the function testable.
func runInit(dir, name string, force, noApproval bool, httpPort int, binPath string, errOut, out io.Writer) error {
	keyPath := filepath.Join(dir, name+".pem")
	pubPath := filepath.Join(dir, name+".pem.pub")
	dbPath := filepath.Join(dir, "receipts.db")

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	// MkdirAll does not tighten permissions on an existing directory, so chmod
	// explicitly to ensure private keys are never stored under a world-readable path.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("set permissions on directory %q: %w", dir, err)
	}

	// Key generation — idempotent when the full keypair already exists.
	_, keyErr := os.Stat(keyPath)
	_, pubErr := os.Stat(pubPath)
	keyPresent := keyErr == nil
	pubPresent := pubErr == nil

	if !force && keyPresent && pubPresent {
		// Both files exist: warn and skip (safe re-run).
		fmt.Fprintf(errOut, "warning: key files already exist — skipping key generation (use -force to overwrite)\n")
		fmt.Fprintf(errOut, "  private key: %s\n", keyPath)
		fmt.Fprintf(errOut, "  public key:  %s\n", pubPath)
	} else if !force && keyPresent != pubPresent {
		// Partial keypair: unsafe to continue without -force.
		presentPath, missingPath := pubPath, keyPath
		if keyPresent {
			presentPath, missingPath = keyPath, pubPath
		}
		return fmt.Errorf("incomplete keypair: found %q but missing %q; rerun with -force to overwrite and regenerate", presentPath, missingPath)
	} else {
		kp, err := receipt.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate key pair: %w", err)
		}
		if err := writePrivateKeyFile(keyPath, []byte(kp.PrivateKey), force); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
		if err := writePubKeyFile(pubPath, []byte(kp.PublicKey), force); err != nil {
			return fmt.Errorf("write public key: %w", err)
		}
		fmt.Fprintf(errOut, "Generated Ed25519 key pair:\n  private: %s\n  public:  %s\n", keyPath, pubPath)
	}

	// Initialise receipt DB — store.Open uses CREATE TABLE IF NOT EXISTS so this is idempotent.
	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("create receipt database: %w", err)
	}
	if cerr := s.Close(); cerr != nil {
		return fmt.Errorf("close receipt database: %w", cerr)
	}
	fmt.Fprintf(errOut, "Receipt database: %s\n", dbPath)

	// Build config snippet. The default policy always contains pause/block rules,
	// so include -http by default; --no-approval opts out.
	proxyArgs := []string{"-key", keyPath, "-receipt-db", dbPath}
	if !noApproval {
		proxyArgs = append(proxyArgs, "-http", fmt.Sprintf("127.0.0.1:%d", httpPort))
	}
	proxyArgs = append(proxyArgs, "YOUR_MCP_SERVER_COMMAND", "AND_ITS_ARGS")

	snippet := map[string]any{
		"mcpServers": map[string]any{
			name: map[string]any{
				"command": binPath,
				"args":    proxyArgs,
			},
		},
	}
	enc, err := json.MarshalIndent(snippet, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config snippet: %w", err)
	}

	fmt.Fprintf(errOut, "\nAdd to your claude_desktop_config.json (replace the trailing args with your MCP server):\n")
	fmt.Fprintln(out, string(enc))
	return nil
}
