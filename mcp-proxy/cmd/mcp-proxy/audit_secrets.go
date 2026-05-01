package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
)

func cmdAuditSecrets(args []string) {
	os.Exit(runAuditSecrets(args, os.Stdout, os.Stderr))
}

// runAuditSecrets scans the audit database for unredacted secrets using
// all built-in patterns and optional custom patterns loaded from a YAML file.
// It returns 0 if no matches are found, 1 if any are found, and 2 on error.
func runAuditSecrets(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-secrets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", defaultDBPath("audit.db"), "Audit database path")
	customPath := fs.String("redact-patterns", "", "Path to YAML file with custom redaction patterns to also scan for")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	s, err := audit.OpenReadOnly(*db)
	if err != nil {
		fmt.Fprintf(stderr, "Error opening audit store: %v\n", err)
		return 2
	}
	defer s.Close()

	// Collect all named patterns: built-ins + custom.
	named := audit.BuiltinPatterns()

	if *customPath != "" {
		custom, err := audit.LoadPatterns(*customPath)
		if err != nil {
			fmt.Fprintf(stderr, "Error loading custom patterns: %v\n", err)
			return 2
		}
		named = append(named, custom...)
	}

	// Optional decryption: if the DB was encrypted we must decrypt before scanning.
	var enc *audit.Encryptor
	if key := os.Getenv("BEACON_ENCRYPTION_KEY"); key != "" {
		salt, present, err := s.EncryptionSaltIfPresent()
		if err != nil {
			fmt.Fprintf(stderr, "Error reading encryption salt: %v\n", err)
			return 2
		}
		if !present {
			fmt.Fprintf(stderr, "Error: BEACON_ENCRYPTION_KEY is set but no encryption salt is recorded in the DB (was the DB ever encrypted?)\n")
			return 2
		}
		var encErr error
		enc, encErr = audit.NewEncryptor(key, salt)
		if encErr != nil {
			fmt.Fprintf(stderr, "Error initialising decryptor: %v\n", encErr)
			return 2
		}
	}

	hits := 0
	scanErr := s.ScanRedactionTargets(func(table, column string, rowID int64, value string) error {
		// If no key is configured but the row is ciphertext, report it: the
		// scanner cannot inspect the plaintext, so operators must investigate.
		if enc == nil && len(value) >= len("enc:") && value[:4] == "enc:" {
			fmt.Fprintf(stdout, "%s col=%s row=%d encrypted-no-key\n", table, column, rowID)
			hits++
			return nil
		}
		plaintext, decErr := enc.Decrypt(value)
		if decErr != nil {
			// Count as a hit — operators must investigate. Do not include the
			// error message or ciphertext (they might leak information).
			fmt.Fprintf(stdout, "%s col=%s row=%d decrypt-error\n", table, column, rowID)
			hits++
			return nil
		}
		for _, p := range named {
			if p.Re.MatchString(plaintext) {
				fmt.Fprintf(stdout, "%s col=%s row=%d pattern=%s\n", table, column, rowID, p.Name)
				hits++
			}
		}
		for _, path := range audit.ScanJSONLeaks(plaintext) {
			fmt.Fprintf(stdout, "%s col=%s row=%d json-key=%s\n", table, column, rowID, path)
			hits++
		}
		return nil
	})
	if scanErr != nil {
		fmt.Fprintf(stderr, "Error: %v\n", scanErr)
		return 2
	}

	if hits > 0 {
		return 1
	}
	return 0
}
