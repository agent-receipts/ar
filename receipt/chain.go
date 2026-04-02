package receipt

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
	BrokenAt int                   `json:"broken_at"` // -1 if chain is valid.
	Error    string                `json:"error,omitempty"` // Non-empty if verification failed due to a key/proof error.
}

// VerifyChain verifies a chain of signed receipts. It checks:
//   - Ed25519 signature validity
//   - Hash linkage (previous_receipt_hash matches SHA-256 of prior receipt)
//   - Sequence numbers strictly incrementing from the first receipt
func VerifyChain(receipts []AgentReceipt, publicKeyPEM string) ChainVerification {
	if len(receipts) == 0 {
		return ChainVerification{Valid: true, Length: 0, BrokenAt: -1}
	}

	results := make([]ReceiptVerification, 0, len(receipts))
	brokenAt := -1

	for i, r := range receipts {
		chain := r.CredentialSubject.Chain

		sigValid, sigErr := Verify(r, publicKeyPEM)
		if sigErr != nil {
			// Append the failing receipt before returning so Receipts
			// length stays consistent with Length/BrokenAt.
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

	return ChainVerification{
		Valid:    brokenAt == -1,
		Length:   len(receipts),
		Receipts: results,
		BrokenAt: brokenAt,
	}
}
