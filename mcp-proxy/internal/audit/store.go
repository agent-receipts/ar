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
	duration_ms INTEGER
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
	SessionID     string
	RequestMsgID  int64
	ResponseMsgID int64
	ToolName      string
	Arguments     string
	Result        string
	Error         string
	OperationType string
	RiskScore     int
	RiskReasons   []string
	PolicyAction  string
	ApprovedBy    string
	RequestedAt   time.Time
	RespondedAt   time.Time
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
		 approved_by, approved_at, requested_at, responded_at, duration_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tc.SessionID, tc.RequestMsgID, tc.ResponseMsgID, tc.ToolName,
		tc.Arguments, tc.Result, tc.Error,
		tc.OperationType, tc.RiskScore, string(reasons), tc.PolicyAction,
		approvedBy, approvedAt,
		tc.RequestedAt.UTC().Format(time.RFC3339Nano), respondedAt, durationMs,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
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

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}
