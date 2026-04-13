// Package audit provides the SQLite audit store for the MCP proxy.
package audit

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	server_name TEXT NOT NULL,
	server_command TEXT NOT NULL,
	started_at TEXT NOT NULL,
	ended_at TEXT
);

CREATE TABLE IF NOT EXISTS messages (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL REFERENCES sessions(id),
	direction TEXT NOT NULL,
	timestamp TEXT NOT NULL,
	jsonrpc_id TEXT,
	method TEXT,
	raw TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_calls (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL REFERENCES sessions(id),
	request_msg_id INTEGER REFERENCES messages(id),
	response_msg_id INTEGER REFERENCES messages(id),
	tool_name TEXT NOT NULL,
	arguments TEXT,
	result TEXT,
	error TEXT,
	operation_type TEXT NOT NULL DEFAULT 'unknown',
	risk_score INTEGER NOT NULL DEFAULT 0,
	risk_reasons TEXT,
	policy_action TEXT NOT NULL DEFAULT 'pass',
	approved_by TEXT,
	approved_at TEXT,
	requested_at TEXT NOT NULL,
	responded_at TEXT,
	duration_ms INTEGER,
	policy_eval_us INTEGER,
	approval_wait_us INTEGER,
	upstream_us INTEGER,
	receipt_sign_us INTEGER
);

CREATE TABLE IF NOT EXISTS intent_contexts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL REFERENCES sessions(id),
	human_prompt TEXT,
	prompt_summary TEXT,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intent_tool_calls (
	intent_id INTEGER NOT NULL REFERENCES intent_contexts(id),
	tool_call_id INTEGER NOT NULL REFERENCES tool_calls(id),
	sequence_order INTEGER NOT NULL,
	PRIMARY KEY (intent_id, tool_call_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_tool_calls_session ON tool_calls(session_id, requested_at);
CREATE INDEX IF NOT EXISTS idx_tool_calls_risk ON tool_calls(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_policy ON tool_calls(policy_action) WHERE policy_action != 'pass';
CREATE INDEX IF NOT EXISTS idx_intent_tool_calls_intent ON intent_tool_calls(intent_id);

CREATE TABLE IF NOT EXISTS metadata (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// Store is the SQLite audit store.
type Store struct {
	db *sql.DB
}

// ToolCallRecord holds a completed tool call for insertion.
type ToolCallRecord struct {
	SessionID      string
	RequestMsgID   int64
	ResponseMsgID  int64
	ToolName       string
	Arguments      string
	Result         string
	Error          string
	OperationType  string
	RiskScore      int
	RiskReasons    []string
	PolicyAction   string
	ApprovedBy     string
	RequestedAt    time.Time
	RespondedAt    time.Time
	PolicyEvalUs   *int64
	ApprovalWaitUs *int64
	UpstreamUs     *int64
	ReceiptSignUs  *int64
}

// Open opens or creates the audit database.
func Open(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." && dir != ":memory:" && dbPath != ":memory:" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("set %s: %w", pragma, err)
		}
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// CreateSession creates a new audit session.
func (s *Store) CreateSession(id, serverName, serverCommand string) error {
	_, err := s.db.Exec(
		"INSERT INTO sessions (id, server_name, server_command, started_at) VALUES (?, ?, ?, ?)",
		id, serverName, serverCommand, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// EndSession marks a session as ended.
func (s *Store) EndSession(id string) error {
	_, err := s.db.Exec(
		"UPDATE sessions SET ended_at = ? WHERE id = ?",
		time.Now().UTC().Format(time.RFC3339), id,
	)
	return err
}

// LogMessage logs a raw JSON-RPC message.
func (s *Store) LogMessage(sessionID, direction, jsonrpcID, method, raw string) (int64, error) {
	result, err := s.db.Exec(
		"INSERT INTO messages (session_id, direction, timestamp, jsonrpc_id, method, raw) VALUES (?, ?, ?, ?, ?, ?)",
		sessionID, direction, time.Now().UTC().Format(time.RFC3339Nano), jsonrpcID, method, raw,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// InsertToolCall inserts a completed tool call record.
func (s *Store) InsertToolCall(tc ToolCallRecord) (int64, error) {
	reasons, _ := json.Marshal(tc.RiskReasons)
	var durationMs *int64
	if !tc.RespondedAt.IsZero() {
		d := tc.RespondedAt.Sub(tc.RequestedAt).Milliseconds()
		durationMs = &d
	}

	var respondedAt *string
	if !tc.RespondedAt.IsZero() {
		s := tc.RespondedAt.UTC().Format(time.RFC3339Nano)
		respondedAt = &s
	}

	var approvedBy *string
	var approvedAt *string
	if tc.ApprovedBy != "" {
		approvedBy = &tc.ApprovedBy
		now := time.Now().UTC().Format(time.RFC3339)
		approvedAt = &now
	}

	result, err := s.db.Exec(`
		INSERT INTO tool_calls
		(session_id, request_msg_id, response_msg_id, tool_name, arguments,
		 result, error, operation_type, risk_score, risk_reasons, policy_action,
		 approved_by, approved_at, requested_at, responded_at, duration_ms,
		 policy_eval_us, approval_wait_us, upstream_us, receipt_sign_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tc.SessionID, tc.RequestMsgID, tc.ResponseMsgID, tc.ToolName,
		tc.Arguments, tc.Result, tc.Error,
		tc.OperationType, tc.RiskScore, string(reasons), tc.PolicyAction,
		approvedBy, approvedAt,
		tc.RequestedAt.UTC().Format(time.RFC3339Nano), respondedAt, durationMs,
		tc.PolicyEvalUs, tc.ApprovalWaitUs, tc.UpstreamUs, tc.ReceiptSignUs,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// UpdateReceiptSignUs updates the receipt_sign_us timing for a tool call.
func (s *Store) UpdateReceiptSignUs(toolCallID int64, us int64) error {
	_, err := s.db.Exec(`UPDATE tool_calls SET receipt_sign_us = ? WHERE id = ?`, us, toolCallID)
	return err
}

// CreateIntentContext creates a new intent grouping.
func (s *Store) CreateIntentContext(sessionID string) (int64, error) {
	result, err := s.db.Exec(
		"INSERT INTO intent_contexts (session_id, created_at) VALUES (?, ?)",
		sessionID, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// LinkToolCallToIntent links a tool call to an intent context.
func (s *Store) LinkToolCallToIntent(intentID, toolCallID int64, seqOrder int) error {
	_, err := s.db.Exec(
		"INSERT INTO intent_tool_calls (intent_id, tool_call_id, sequence_order) VALUES (?, ?, ?)",
		intentID, toolCallID, seqOrder,
	)
	return err
}

// EncryptionSalt returns the per-installation encryption salt, generating and
// persisting a random 16-byte salt on first use. Concurrent callers are safe:
// INSERT OR IGNORE + re-SELECT ensures all callers converge on the same salt.
func (s *Store) EncryptionSalt() ([]byte, error) {
	var encoded string
	err := s.db.QueryRow("SELECT value FROM metadata WHERE key = 'encryption_salt'").Scan(&encoded)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query encryption salt: %w", err)
	}
	if err == sql.ErrNoRows {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate encryption salt: %w", err)
		}
		encoded = hex.EncodeToString(salt)
		if _, err := s.db.Exec("INSERT OR IGNORE INTO metadata (key, value) VALUES ('encryption_salt', ?)", encoded); err != nil {
			return nil, fmt.Errorf("persist encryption salt: %w", err)
		}
		// Re-read to handle the race: another caller may have inserted first.
		if err := s.db.QueryRow("SELECT value FROM metadata WHERE key = 'encryption_salt'").Scan(&encoded); err != nil {
			return nil, fmt.Errorf("query persisted encryption salt: %w", err)
		}
	}
	salt, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode encryption salt: %w", err)
	}
	if len(salt) != 16 {
		return nil, fmt.Errorf("invalid encryption salt length: got %d, want 16", len(salt))
	}
	return salt, nil
}

// ToolTiming holds per-tool aggregate timing data.
type ToolTiming struct {
	ToolName      string `json:"tool_name"`
	Count         int    `json:"count"`
	AvgUpstreamUs *int64 `json:"avg_upstream_us"`
	AvgPolicyUs   *int64 `json:"avg_policy_eval_us"`
	AvgReceiptUs  *int64 `json:"avg_receipt_sign_us"`
	AvgApprovalUs *int64 `json:"avg_approval_wait_us"`
	AvgDurationMs *int64 `json:"avg_duration_ms"`
}

// Percentiles holds p50/p95/p99 values for a timing phase.
type Percentiles struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
}

// TimingStats holds aggregate timing data for tool calls.
type TimingStats struct {
	Total       int                    `json:"total"`
	ByTool      []ToolTiming           `json:"by_tool"`
	Percentiles map[string]Percentiles `json:"percentiles"`
}

// TimingStats queries aggregate timing data from the tool_calls table.
// If sessionID is non-empty, results are filtered to that session.
func (s *Store) TimingStats(sessionID string, limit int) (TimingStats, error) {
	var st TimingStats

	// Total count.
	countQuery := "SELECT COUNT(*) FROM tool_calls WHERE duration_ms IS NOT NULL"
	args := []any{}
	if sessionID != "" {
		countQuery += " AND session_id = ?"
		args = append(args, sessionID)
	}
	if err := s.db.QueryRow(countQuery, args...).Scan(&st.Total); err != nil {
		return TimingStats{}, err
	}
	if st.Total == 0 {
		st.ByTool = []ToolTiming{}
		st.Percentiles = map[string]Percentiles{}
		return st, nil
	}

	// Per-tool averages.
	toolQuery := `SELECT tool_name, COUNT(*),
		AVG(upstream_us), AVG(policy_eval_us), AVG(receipt_sign_us),
		AVG(approval_wait_us), AVG(duration_ms)
		FROM tool_calls WHERE duration_ms IS NOT NULL`
	toolArgs := []any{}
	if sessionID != "" {
		toolQuery += " AND session_id = ?"
		toolArgs = append(toolArgs, sessionID)
	}
	toolQuery += " GROUP BY tool_name ORDER BY COUNT(*) DESC"
	if limit > 0 {
		toolQuery += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(toolQuery, toolArgs...)
	if err != nil {
		return TimingStats{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var tt ToolTiming
		var avgUpstream, avgPolicy, avgReceipt, avgApproval, avgDuration *float64
		if err := rows.Scan(&tt.ToolName, &tt.Count,
			&avgUpstream, &avgPolicy, &avgReceipt,
			&avgApproval, &avgDuration); err != nil {
			return TimingStats{}, err
		}
		tt.AvgUpstreamUs = floatToInt64(avgUpstream)
		tt.AvgPolicyUs = floatToInt64(avgPolicy)
		tt.AvgReceiptUs = floatToInt64(avgReceipt)
		tt.AvgApprovalUs = floatToInt64(avgApproval)
		tt.AvgDurationMs = floatToInt64(avgDuration)
		st.ByTool = append(st.ByTool, tt)
	}
	if err := rows.Err(); err != nil {
		return TimingStats{}, err
	}

	// Percentiles via ordered subqueries.
	st.Percentiles = map[string]Percentiles{}
	phases := []struct {
		name   string
		column string
	}{
		{"upstream", "upstream_us"},
		{"policy_eval", "policy_eval_us"},
		{"receipt_sign", "receipt_sign_us"},
		{"duration_ms", "duration_ms"},
	}
	for _, phase := range phases {
		p, err := s.percentiles(phase.column, sessionID)
		if err != nil {
			return TimingStats{}, err
		}
		if p != nil {
			st.Percentiles[phase.name] = *p
		}
	}

	return st, nil
}

// percentiles computes p50/p95/p99 for a column using ordered offset.
func (s *Store) percentiles(column, sessionID string) (*Percentiles, error) {
	where := fmt.Sprintf("WHERE %s IS NOT NULL AND duration_ms IS NOT NULL", column)
	args := []any{}
	if sessionID != "" {
		where += " AND session_id = ?"
		args = append(args, sessionID)
	}

	var total int
	countQ := fmt.Sprintf("SELECT COUNT(*) FROM tool_calls %s", where)
	if err := s.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, err
	}
	if total == 0 {
		return nil, nil
	}

	valueAt := func(pct float64) (int64, error) {
		idx := int(float64(total)*pct) - 1
		if idx < 0 {
			idx = 0
		}
		q := fmt.Sprintf("SELECT %s FROM tool_calls %s ORDER BY %s LIMIT 1 OFFSET ?",
			column, where, column)
		a := append(append([]any{}, args...), idx)
		var val int64
		if err := s.db.QueryRow(q, a...).Scan(&val); err != nil {
			return 0, err
		}
		return val, nil
	}

	p50, err := valueAt(0.50)
	if err != nil {
		return nil, err
	}
	p95, err := valueAt(0.95)
	if err != nil {
		return nil, err
	}
	p99, err := valueAt(0.99)
	if err != nil {
		return nil, err
	}

	return &Percentiles{P50: p50, P95: p95, P99: p99}, nil
}

func floatToInt64(f *float64) *int64 {
	if f == nil {
		return nil
	}
	v := int64(*f)
	return &v
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}
