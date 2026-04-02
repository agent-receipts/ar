package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

func openReceiptStore(path string) *store.Store {
	s, err := store.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening receipt store: %v\n", err)
		os.Exit(1)
	}
	return s
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	db := fs.String("receipt-db", "receipts.db", "Receipt store path")
	chainID := fs.String("chain", "", "Filter by chain ID")
	riskLevel := fs.String("risk", "", "Filter by risk level")
	actionType := fs.String("action", "", "Filter by action type")
	asJSON := fs.Bool("json", false, "Output as JSON")
	limit := fs.Int("limit", 50, "Max results")
	fs.Parse(args)

	s := openReceiptStore(*db)
	defer s.Close()

	q := store.Query{Limit: limit}
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

	fmt.Printf("%-40s %-30s %-8s %-10s %s\n", "ID", "ACTION", "RISK", "STATUS", "TIMESTAMP")
	fmt.Println("---")
	for _, r := range receipts {
		subj := r.CredentialSubject
		fmt.Printf("%-40s %-30s %-8s %-10s %s\n",
			truncate(r.ID, 40),
			subj.Action.Type,
			subj.Action.RiskLevel,
			subj.Outcome.Status,
			subj.Action.Timestamp,
		)
	}
	fmt.Printf("\n%d receipts\n", len(receipts))
}

func cmdInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	db := fs.String("receipt-db", "receipts.db", "Receipt store path")
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
	db := fs.String("receipt-db", "receipts.db", "Receipt store path")
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
	db := fs.String("receipt-db", "receipts.db", "Receipt store path")
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
	db := fs.String("receipt-db", "receipts.db", "Receipt store path")
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
