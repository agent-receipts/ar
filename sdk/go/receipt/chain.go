package receipt

import (
	"encoding/json"
	"strconv"
)

// ReceiptVerification holds the verification result for a single receipt in a chain.
type ReceiptVerification struct {
	Index          int    `json:"index"`
	ReceiptID      string `json:"receipt_id"`
	SignatureValid bool   `json:"signature_valid"`
	HashLinkValid  bool   `json:"hash_link_valid"`
	SequenceValid  bool   `json:"sequence_valid"`
}

// ChainVerification holds the verification result for an entire chain.
type ChainVerification struct {
	Valid    bool                  `json:"valid"`
	Length   int                   `json:"length"`
	Receipts []ReceiptVerification `json:"receipts"`
	BrokenAt int                   `json:"broken_at"`       // -1 if chain is valid.
	Error    string                `json:"error,omitempty"` // Non-empty if verification failed due to a key/proof error.
	// ResponseHashNote is non-empty when one or more receipts carry response_hash
	// but no response body was supplied for recomputation.
	ResponseHashNote string `json:"response_hash_note,omitempty"`
}

// ChainVerifyOptions holds optional parameters for VerifyChain.
// Zero value means "use defaults" — behaviour is identical to v0.1 with no options.
type ChainVerifyOptions struct {
	// ExpectedLength, when non-nil, causes verification to fail if the observed
	// chain length does not equal this value. Provides out-of-band truncation
	// detection when the caller knows the expected chain length.
	ExpectedLength *int

	// ExpectedFinalHash, when non-empty, causes verification to fail if the
	// SHA-256 hash of the last observed receipt does not equal this value.
	// Provides out-of-band truncation detection when the caller knows the
	// expected final receipt hash.
	ExpectedFinalHash string

	// RequireTerminal, when true, causes verification to fail if the last
	// observed receipt does not have chain.terminal: true. Use for chains
	// that must close cleanly. When false (the default), absence of a terminal
	// marker is not a failure.
	RequireTerminal bool

	// ResponseBodies maps receipt ID → pre-redacted response body (JSON-encoded).
	// When a receipt carries outcome.response_hash and its ID appears here,
	// VerifyChain recomputes the hash (canonicalize → SHA-256) and fails on
	// mismatch. When an entry is absent the verifier emits an informational note
	// instead (see ChainVerification.ResponseHashNote). An absent body is not a
	// verification failure.
	ResponseBodies map[string]json.RawMessage
}

// VerifyChain verifies a chain of signed receipts. It checks:
//   - Ed25519 signature validity
//   - Hash linkage (previous_receipt_hash matches SHA-256 of prior receipt)
//   - Sequence numbers strictly incrementing from the first receipt
//   - Receipt-after-terminal: if any receipt has chain.terminal: true, no
//     subsequent receipt may reference it (unconditional check, see spec §7.3.2)
//
// Chain verification does NOT detect tail truncation by default — dropping the
// last N receipts from a chain still produces Valid: true. To detect truncation:
//   - Supply ExpectedLength and/or ExpectedFinalHash (out-of-band witness)
//   - Supply RequireTerminal for chains that must close with chain.terminal: true
//
// Chains that are open-ended and have no external witness cannot be detected as
// truncated. See spec §7.3.1 for the full treatment.
//
// Supply ResponseBodies to verify outcome.response_hash fields: for each receipt
// whose ID maps to a body, the hash is recomputed and verification fails on
// mismatch. When no body is supplied for a receipt that carries response_hash, an
// informational note is emitted but verification continues.
func VerifyChain(receipts []AgentReceipt, publicKeyPEM string, opts ...ChainVerifyOptions) ChainVerification {
	var opt ChainVerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	if len(receipts) == 0 {
		// Handle ExpectedLength=0 edge case: empty chain with ExpectedLength=0 is valid.
		if opt.ExpectedLength != nil && *opt.ExpectedLength != 0 {
			return ChainVerification{
				Valid:    false,
				Length:   0,
				BrokenAt: 0,
				Error:    "expected chain length does not match: expected " + strconv.Itoa(*opt.ExpectedLength) + ", got 0",
			}
		}
		return ChainVerification{Valid: true, Length: 0, BrokenAt: -1}
	}

	results := make([]ReceiptVerification, 0, len(receipts))
	brokenAt := -1

	for i, r := range receipts {
		chain := r.CredentialSubject.Chain

		sigValid, sigErr := Verify(r, publicKeyPEM)
		if sigErr != nil {
			results = append(results, ReceiptVerification{
				Index:          i,
				ReceiptID:      r.ID,
				SignatureValid: false,
				HashLinkValid:  false,
				SequenceValid:  false,
			})
			return ChainVerification{
				Valid:    false,
				Length:   len(receipts),
				Receipts: results,
				BrokenAt: i,
				Error:    sigErr.Error(),
			}
		}

		hashValid := true
		if i == 0 {
			hashValid = chain.PreviousReceiptHash == nil
		} else {
			prevHash, err := HashReceipt(receipts[i-1])
			if err != nil {
				hashValid = false
			} else {
				hashValid = chain.PreviousReceiptHash != nil && *chain.PreviousReceiptHash == prevHash
			}
		}

		seqValid := true
		if i == 0 {
			seqValid = chain.Sequence >= 1
		} else {
			seqValid = chain.Sequence == receipts[i-1].CredentialSubject.Chain.Sequence+1
		}

		results = append(results, ReceiptVerification{
			Index:          i,
			ReceiptID:      r.ID,
			SignatureValid: sigValid,
			HashLinkValid:  hashValid,
			SequenceValid:  seqValid,
		})

		if brokenAt == -1 && (!sigValid || !hashValid || !seqValid) {
			brokenAt = i
		}
	}

	// Receipt-after-terminal integrity check (unconditional — spec §7.3.2).
	// If a receipt has terminal: true and is not the last receipt, that is a
	// protocol violation: a receipt after a terminal predecessor exists.
	for i, r := range receipts {
		ch := r.CredentialSubject.Chain
		if ch.Terminal != nil && *ch.Terminal {
			if i < len(receipts)-1 {
				if brokenAt == -1 {
					brokenAt = i + 1
				}
				return ChainVerification{
					Valid:    false,
					Length:   len(receipts),
					Receipts: results,
					BrokenAt: brokenAt,
					Error:    "receipt after terminal: receipt at index " + strconv.Itoa(i+1) + " follows a terminal receipt at index " + strconv.Itoa(i),
				}
			}
		}
	}

	cv := ChainVerification{
		Valid:    brokenAt == -1,
		Length:   len(receipts),
		Receipts: results,
		BrokenAt: brokenAt,
	}

	// Response-hash verification (spec §4.3.2).
	// When a body is supplied: recompute and fail on mismatch.
	// When the body is absent: emit an informational note only.
	for i, r := range receipts {
		expectedHash := r.CredentialSubject.Outcome.ResponseHash
		if expectedHash == "" {
			continue
		}
		body, hasBody := opt.ResponseBodies[r.ID]
		if !hasBody {
			cv.ResponseHashNote = "response_hash present in one or more receipts; response body not supplied — hash cannot be verified offline"
			continue
		}
		if !cv.Valid {
			// Chain already broken; skip comparison.
			continue
		}
		var bodyAny any
		if err := json.Unmarshal(body, &bodyAny); err != nil {
			cv.Valid = false
			cv.BrokenAt = i
			cv.Error = "response_hash: failed to parse response body at index " + strconv.Itoa(i) + ": " + err.Error()
			return cv
		}
		canonical, err := Canonicalize(bodyAny)
		if err != nil {
			cv.Valid = false
			cv.BrokenAt = i
			cv.Error = "response_hash: failed to canonicalize response body at index " + strconv.Itoa(i) + ": " + err.Error()
			return cv
		}
		computed := SHA256Hash(canonical)
		if computed != expectedHash {
			cv.Valid = false
			cv.BrokenAt = i
			cv.Error = "response_hash mismatch at index " + strconv.Itoa(i) + ": receipt has " + expectedHash + ", body hashes to " + computed
			return cv
		}
	}

	if cv.Valid {
		// Optional out-of-band checks (only applied when basic verification passes).
		if opt.ExpectedLength != nil && len(receipts) != *opt.ExpectedLength {
			cv.Valid = false
			cv.BrokenAt = len(receipts) - 1
			cv.Error = "expected chain length does not match: expected " + strconv.Itoa(*opt.ExpectedLength) + ", got " + strconv.Itoa(len(receipts))
		} else if opt.ExpectedFinalHash != "" {
			lastHash, err := HashReceipt(receipts[len(receipts)-1])
			if err != nil || lastHash != opt.ExpectedFinalHash {
				cv.Valid = false
				cv.BrokenAt = len(receipts) - 1
				cv.Error = "final receipt hash does not match expected value"
			}
		}

		if cv.Valid && opt.RequireTerminal {
			last := receipts[len(receipts)-1]
			if last.CredentialSubject.Chain.Terminal == nil || !*last.CredentialSubject.Chain.Terminal {
				cv.Valid = false
				cv.BrokenAt = len(receipts) - 1
				cv.Error = "require_terminal: last receipt does not have chain.terminal: true"
			}
		}
	}

	return cv
}
