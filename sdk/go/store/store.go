// Package store provides SQLite-backed persistence for Action Receipts.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agent-receipts/ar/sdk/go/receipt"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS receipts (
	id TEXT PRIMARY KEY,
	chain_id TEXT NOT NULL,
	sequence INTEGER NOT NULL,
	action_type TEXT NOT NULL,
	risk_level TEXT NOT NULL,
	status TEXT NOT NULL,
	timestamp TEXT NOT NULL,
	issuer_id TEXT NOT NULL,
	principal_id TEXT,
	receipt_json TEXT NOT NULL,
	receipt_hash TEXT NOT NULL,
	previous_receipt_hash TEXT,
	created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_chain ON receipts(chain_id, sequence);
CREATE INDEX IF NOT EXISTS idx_receipts_action ON receipts(action_type);
CREATE INDEX IF NOT EXISTS idx_receipts_risk ON receipts(risk_level);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
`

// ReceiptStore defines the interface for receipt persistence and querying.
type ReceiptStore interface {
	Insert(r receipt.AgentReceipt, receiptHash string) error
	GetByID(id string) (*receipt.AgentReceipt, error)
	GetChain(chainID string) ([]receipt.AgentReceipt, error)
	QueryReceipts(q Query) ([]receipt.AgentReceipt, error)
	Stats() (Stats, error)
	VerifyStoredChain(chainID string, publicKeyPEM string) (receipt.ChainVerification, error)
	Close() error
}

// Store is a SQLite-backed receipt store.
type Store struct {
	db *sql.DB
}

// Query filters for querying receipts.
type Query struct {
	ChainID    *string
	ActionType *string
	RiskLevel  *receipt.RiskLevel
	Status     *receipt.OutcomeStatus
	After      *string // ISO 8601 timestamp
	Before     *string // ISO 8601 timestamp
	Limit      *int    // Default 10000
}

// Stats holds aggregate statistics for the store.
type Stats struct {
	Total    int           `json:"total"`
	Chains   int           `json:"chains"`
	ByRisk   []GroupCount  `json:"by_risk"`
	ByStatus []GroupCount  `json:"by_status"`
	ByAction []GroupCount  `json:"by_action"`
}

// GroupCount is a label + count pair used in Stats.
type GroupCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// Open opens or creates a receipt store at the given path.
// Use ":memory:" for an in-memory database.
func Open(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// Enable WAL mode and set busy timeout for concurrent access.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("set %s: %w", pragma, err)
		}
	}
	db.SetMaxOpenConns(1) // SQLite serializes writes; one conn avoids contention.
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Insert persists a signed receipt with its precomputed hash.
func (s *Store) Insert(r receipt.AgentReceipt, receiptHash string) error {
	subj := r.CredentialSubject
	rJSON, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal receipt: %w", err)
	}

	var prevHash *string
	if subj.Chain.PreviousReceiptHash != nil {
		prevHash = subj.Chain.PreviousReceiptHash
	}

	_, err = s.db.Exec(`
		INSERT INTO receipts
		(id, chain_id, sequence, action_type, risk_level, status,
		 timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
		 previous_receipt_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID,
		subj.Chain.ChainID,
		subj.Chain.Sequence,
		subj.Action.Type,
		string(subj.Action.RiskLevel),
		string(subj.Outcome.Status),
		subj.Action.Timestamp,
		r.Issuer.ID,
		subj.Principal.ID,
		string(rJSON),
		receiptHash,
		prevHash,
	)
	return err
}

// GetByID retrieves a receipt by its ID. Returns nil if not found.
func (s *Store) GetByID(id string) (*receipt.AgentReceipt, error) {
	var rJSON string
	err := s.db.QueryRow("SELECT receipt_json FROM receipts WHERE id = ?", id).Scan(&rJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r receipt.AgentReceipt
	if err := json.Unmarshal([]byte(rJSON), &r); err != nil {
		return nil, fmt.Errorf("corrupt receipt (id=%s): %w", id, err)
	}
	return &r, nil
}

// GetChain retrieves all receipts in a chain, ordered by sequence.
func (s *Store) GetChain(chainID string) ([]receipt.AgentReceipt, error) {
	rows, err := s.db.Query(
		"SELECT receipt_json FROM receipts WHERE chain_id = ? ORDER BY sequence ASC",
		chainID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReceipts(rows)
}

// QueryReceipts retrieves receipts matching the given filters.
func (s *Store) QueryReceipts(q Query) ([]receipt.AgentReceipt, error) {
	var conds []string
	var args []any

	if q.ChainID != nil {
		conds = append(conds, "chain_id = ?")
		args = append(args, *q.ChainID)
	}
	if q.ActionType != nil {
		conds = append(conds, "action_type = ?")
		args = append(args, *q.ActionType)
	}
	if q.RiskLevel != nil {
		conds = append(conds, "risk_level = ?")
		args = append(args, string(*q.RiskLevel))
	}
	if q.Status != nil {
		conds = append(conds, "status = ?")
		args = append(args, string(*q.Status))
	}
	if q.After != nil {
		conds = append(conds, "timestamp >= ?")
		args = append(args, *q.After)
	}
	if q.Before != nil {
		conds = append(conds, "timestamp <= ?")
		args = append(args, *q.Before)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	limit := 10000
	if q.Limit != nil {
		limit = *q.Limit
	}

	query := fmt.Sprintf(
		"SELECT receipt_json FROM receipts %s ORDER BY timestamp ASC LIMIT ?",
		where,
	)
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReceipts(rows)
}

// Stats returns aggregate statistics for the store.
func (s *Store) Stats() (Stats, error) {
	var st Stats

	if err := s.db.QueryRow("SELECT COUNT(*) FROM receipts").Scan(&st.Total); err != nil {
		return Stats{}, err
	}
	if err := s.db.QueryRow("SELECT COUNT(DISTINCT chain_id) FROM receipts").Scan(&st.Chains); err != nil {
		return Stats{}, err
	}

	var err error
	st.ByRisk, err = s.groupBy("risk_level")
	if err != nil {
		return Stats{}, err
	}
	st.ByStatus, err = s.groupBy("status")
	if err != nil {
		return Stats{}, err
	}
	st.ByAction, err = s.groupBy("action_type")
	if err != nil {
		return Stats{}, err
	}

	return st, nil
}

// VerifyStoredChain loads a chain from the store and verifies it.
func (s *Store) VerifyStoredChain(chainID string, publicKeyPEM string) (receipt.ChainVerification, error) {
	receipts, err := s.GetChain(chainID)
	if err != nil {
		return receipt.ChainVerification{}, fmt.Errorf("load chain: %w", err)
	}
	return receipt.VerifyChain(receipts, publicKeyPEM), nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

var allowedGroupByColumns = map[string]bool{
	"risk_level":  true,
	"status":      true,
	"action_type": true,
}

func (s *Store) groupBy(column string) ([]GroupCount, error) {
	if !allowedGroupByColumns[column] {
		return nil, fmt.Errorf("invalid group-by column: %q", column)
	}
	query := fmt.Sprintf(
		"SELECT %s, COUNT(*) FROM receipts GROUP BY %s ORDER BY COUNT(*) DESC",
		column, column,
	)
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GroupCount
	for rows.Next() {
		var gc GroupCount
		if err := rows.Scan(&gc.Label, &gc.Count); err != nil {
			return nil, err
		}
		out = append(out, gc)
	}
	return out, rows.Err()
}

func scanReceipts(rows *sql.Rows) ([]receipt.AgentReceipt, error) {
	var receipts []receipt.AgentReceipt
	for rows.Next() {
		var rJSON string
		if err := rows.Scan(&rJSON); err != nil {
			return nil, err
		}
		var r receipt.AgentReceipt
		if err := json.Unmarshal([]byte(rJSON), &r); err != nil {
			return nil, fmt.Errorf("corrupt receipt in store: %w", err)
		}
		receipts = append(receipts, r)
	}
	return receipts, rows.Err()
}
