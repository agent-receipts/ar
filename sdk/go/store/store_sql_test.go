package store

import (
	"strings"
	"testing"
)

// TestBuildQueryReceiptsSQLNoLimit verifies that nil Limit omits the LIMIT
// clause entirely. Five rows would still pass with a 10,000-row cap, so this
// white-box check is the real regression guard for the removed cap.
func TestBuildQueryReceiptsSQLNoLimit(t *testing.T) {
	sql, _ := buildQueryReceiptsSQL(Query{})
	if strings.Contains(sql, "LIMIT") {
		t.Errorf("expected no LIMIT clause when Limit is nil, got: %s", sql)
	}
}

// TestBuildQueryReceiptsSQLWithLimit verifies that an explicit Limit adds the
// LIMIT clause.
func TestBuildQueryReceiptsSQLWithLimit(t *testing.T) {
	lim := 50
	sql, _ := buildQueryReceiptsSQL(Query{Limit: &lim})
	if !strings.Contains(sql, "LIMIT") {
		t.Errorf("expected LIMIT clause when Limit is set, got: %s", sql)
	}
}

// TestBuildQueryReceiptsSQLOrderClause verifies rowid is the final tiebreaker.
func TestBuildQueryReceiptsSQLOrderClause(t *testing.T) {
	asc, _ := buildQueryReceiptsSQL(Query{})
	if !strings.Contains(asc, "timestamp ASC, sequence ASC, rowid ASC") {
		t.Errorf("ASC order clause missing rowid tiebreaker: %s", asc)
	}

	desc, _ := buildQueryReceiptsSQL(Query{NewestFirst: true})
	if !strings.Contains(desc, "timestamp DESC, sequence DESC, rowid DESC") {
		t.Errorf("DESC order clause missing rowid tiebreaker: %s", desc)
	}
}
