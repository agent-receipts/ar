// Package store provides SQLite-backed persistence for Action Receipts.
package store

import (
	"context"
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
	tool_name TEXT NOT NULL DEFAULT '',
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
	GetChainTail(chainID string) (sequence int64, receiptHash string, found bool, err error)
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
	// NewestFirst reverses the default ascending-timestamp ordering so the
	// most recent receipts are returned first. Default is false (ascending)
	// to preserve historical behavior.
	NewestFirst bool
}

// Stats holds aggregate statistics for the store.
type Stats struct {
	Total    int          `json:"total"`
	Chains   int          `json:"chains"`
	ByRisk   []GroupCount `json:"by_risk"`
	ByStatus []GroupCount `json:"by_status"`
	ByAction []GroupCount `json:"by_action"`
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
	// Migrate pre-existing databases that lack the tool_name column.
	if err := migrateToolName(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate tool_name: %w", err)
	}
	return &Store{db: db}, nil
}

// migrateToolName adds the tool_name column to existing databases that
// were created before this field existed. It is a no-op when the column
// is already present (i.e. the table was just created by the schema DDL).
func migrateToolName(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(receipts)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt *string
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if name == "tool_name" {
			return nil // column already exists
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE receipts ADD COLUMN tool_name TEXT NOT NULL DEFAULT ''")
	return err
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
		(id, chain_id, sequence, action_type, tool_name, risk_level, status,
		 timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
		 previous_receipt_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID,
		subj.Chain.ChainID,
		subj.Chain.Sequence,
		subj.Action.Type,
		subj.Action.ToolName,
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

// GetChainTail returns the highest-sequence receipt's sequence and hash for
// chainID. found is false (with zero values for the other fields and err nil)
// when the chain is empty. The daemon uses this on startup to resume the
// in-memory (sequence, prev_hash) it owns as sole writer.
func (s *Store) GetChainTail(chainID string) (sequence int64, receiptHash string, found bool, err error) {
	row := s.db.QueryRow(
		"SELECT sequence, receipt_hash FROM receipts WHERE chain_id = ? ORDER BY sequence DESC LIMIT 1",
		chainID,
	)
	if scanErr := row.Scan(&sequence, &receiptHash); scanErr != nil {
		if scanErr == sql.ErrNoRows {
			return 0, "", false, nil
		}
		return 0, "", false, fmt.Errorf("get chain tail (chain_id=%s): %w", chainID, scanErr)
	}
	return sequence, receiptHash, true, nil
}

// QueryReceipts retrieves receipts matching the given filters.
func (s *Store) QueryReceipts(q Query) ([]receipt.AgentReceipt, error) {
	query, args := buildQueryReceiptsSQL(q)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query receipts: %w", err)
	}
	defer rows.Close()
	return scanReceipts(rows)
}

// MaxRowID returns the largest SQLite rowid currently in the receipts table.
// Returns 0 when the table is empty. Intended as the watermark for follow-mode
// streaming — callers pass it to QueryAfterRowID to fetch rows inserted later.
func (s *Store) MaxRowID() (int64, error) {
	var max int64
	if err := s.db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM receipts").Scan(&max); err != nil {
		return 0, fmt.Errorf("max rowid: %w", err)
	}
	return max, nil
}

// QueryAfterRowID returns receipts with rowid > afterRowID that match the
// non-ordering filters in q, ordered ascending by rowid. The returned int64
// is the largest rowid in the result set, or afterRowID when no rows match —
// callers feed it back in to poll for subsequent inserts.
//
// NewestFirst is ignored (follow-mode rows are always chronological). Limit
// defaults to 10000 like QueryReceipts but is typically set much lower when
// polling.
//
// Callers that want to bound query latency (e.g. so Ctrl-C in follow mode
// stops a busy/locked query promptly) should use QueryAfterRowIDContext.
func (s *Store) QueryAfterRowID(q Query, afterRowID int64) ([]receipt.AgentReceipt, int64, error) {
	return s.QueryAfterRowIDContext(context.Background(), q, afterRowID)
}

// QueryAfterRowIDContext is the context-aware form of QueryAfterRowID. When
// ctx is canceled, the in-flight SQLite query is interrupted so callers (e.g.
// follow-mode pollers) don't have to wait on busy_timeout before shutting
// down.
func (s *Store) QueryAfterRowIDContext(ctx context.Context, q Query, afterRowID int64) ([]receipt.AgentReceipt, int64, error) {
	query, args := buildQueryAfterRowIDSQL(q, afterRowID)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, afterRowID, fmt.Errorf("query after rowid %d: %w", afterRowID, err)
	}
	defer rows.Close()
	return scanRowIDReceipts(rows, afterRowID)
}

// QueryReceiptsWithWatermark runs the standard filtered receipt query and
// captures the table's MaxRowID atomically in a single read transaction.
// Intended for follow-mode startup: the returned watermark is consistent with
// the rows emitted, eliminating the race where a row inserted between a
// naive Query + MaxRowID pair can be silently skipped.
//
// Callers that want Ctrl-C to interrupt the startup query should use
// QueryReceiptsWithWatermarkContext.
func (s *Store) QueryReceiptsWithWatermark(q Query) ([]receipt.AgentReceipt, int64, error) {
	return s.QueryReceiptsWithWatermarkContext(context.Background(), q)
}

// QueryReceiptsWithWatermarkContext is the context-aware form of
// QueryReceiptsWithWatermark. The supplied context governs both the
// transaction and each query inside it, so cancellation interrupts in-flight
// work instead of waiting for busy_timeout.
func (s *Store) QueryReceiptsWithWatermarkContext(ctx context.Context, q Query) ([]receipt.AgentReceipt, int64, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("begin read transaction: %w", err)
	}
	defer tx.Rollback()

	query, args := buildQueryReceiptsSQL(q)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query receipts: %w", err)
	}
	receipts, err := scanReceipts(rows)
	rows.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("scan receipts: %w", err)
	}

	var maxRowID int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(rowid), 0) FROM receipts").Scan(&maxRowID); err != nil {
		return nil, 0, fmt.Errorf("max rowid: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("commit read transaction: %w", err)
	}
	return receipts, maxRowID, nil
}

// buildQueryReceiptsSQL builds the SQL and args for QueryReceipts. Extracted
// so QueryReceiptsWithWatermark can run the same query inside a transaction.
func buildQueryReceiptsSQL(q Query) (string, []any) {
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
	order := "ASC"
	if q.NewestFirst {
		order = "DESC"
	}
	query := fmt.Sprintf(
		"SELECT receipt_json FROM receipts %s ORDER BY timestamp %s LIMIT ?",
		where, order,
	)
	args = append(args, limit)
	return query, args
}

// buildQueryAfterRowIDSQL builds the rowid-watermark query SQL + args.
func buildQueryAfterRowIDSQL(q Query, afterRowID int64) (string, []any) {
	conds := []string{"rowid > ?"}
	args := []any{afterRowID}

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

	limit := 10000
	if q.Limit != nil {
		limit = *q.Limit
	}
	args = append(args, limit)

	query := fmt.Sprintf(
		"SELECT rowid, receipt_json FROM receipts WHERE %s ORDER BY rowid ASC LIMIT ?",
		strings.Join(conds, " AND "),
	)
	return query, args
}

func scanRowIDReceipts(rows *sql.Rows, afterRowID int64) ([]receipt.AgentReceipt, int64, error) {
	var receipts []receipt.AgentReceipt
	maxRowID := afterRowID
	for rows.Next() {
		var rowid int64
		var rJSON string
		if err := rows.Scan(&rowid, &rJSON); err != nil {
			return nil, maxRowID, fmt.Errorf("scan receipt row: %w", err)
		}
		var r receipt.AgentReceipt
		if err := json.Unmarshal([]byte(rJSON), &r); err != nil {
			return nil, maxRowID, fmt.Errorf("corrupt receipt in store: %w", err)
		}
		receipts = append(receipts, r)
		if rowid > maxRowID {
			maxRowID = rowid
		}
	}
	if err := rows.Err(); err != nil {
		return nil, maxRowID, fmt.Errorf("iterate receipt rows: %w", err)
	}
	return receipts, maxRowID, nil
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
