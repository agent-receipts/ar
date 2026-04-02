package receipt

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// SHA256Hash computes the SHA-256 hash of data and returns "sha256:<hex>".
func SHA256Hash(data string) string {
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("sha256:%x", h)
}

// HashReceipt computes the SHA-256 hash of a signed receipt (excluding proof).
// Returns the hash in "sha256:<hex>" format.
func HashReceipt(r AgentReceipt) (string, error) {
	unsigned := UnsignedAgentReceipt{
		Context:           r.Context,
		ID:                r.ID,
		Type:              r.Type,
		Version:           r.Version,
		Issuer:            r.Issuer,
		IssuanceDate:      r.IssuanceDate,
		CredentialSubject: r.CredentialSubject,
	}
	canonical, err := Canonicalize(unsigned)
	if err != nil {
		return "", fmt.Errorf("canonicalize receipt: %w", err)
	}
	return SHA256Hash(canonical), nil
}

// Canonicalize serialises v to RFC 8785 canonical JSON.
func Canonicalize(v any) (string, error) {
	// Marshal to JSON first so we work with a generic representation.
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", err
	}
	return canonicalizeValue(generic)
}

func canonicalizeValue(v any) (string, error) {
	if v == nil {
		return "null", nil
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case float64:
		return canonicalizeNumber(val)
	case string:
		b, _ := json.Marshal(val)
		return string(b), nil
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			s, err := canonicalizeValue(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		parts := make([]string, 0, len(val))
		for _, k := range keys {
			keyStr, _ := json.Marshal(k)
			valStr, err := canonicalizeValue(val[k])
			if err != nil {
				return "", err
			}
			parts = append(parts, string(keyStr)+":"+valStr)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fmt.Errorf("unsupported type: %T", v)
	}
}

// canonicalizeNumber formats a float64 according to RFC 8785 §3.2.2.3,
// which mandates the ECMAScript Number.prototype.toString() algorithm.
// This matches the TypeScript SDK's use of String(n).
func canonicalizeNumber(n float64) (string, error) {
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return "", fmt.Errorf("non-finite number: %v", n)
	}
	// -0 must serialize as "0" per RFC 8785.
	if n == 0 {
		return "0", nil
	}
	return es6NumberToString(n), nil
}

// es6NumberToString replicates the ECMAScript Number::toString algorithm
// (ECMA-262 §6.1.6.1.20) which RFC 8785 mandates for number serialization.
//
// The algorithm uses the shortest decimal representation that round-trips
// to the same float64, then applies exponential notation when the exponent
// is < -6 or >= 21.
func es6NumberToString(n float64) string {
	if n < 0 {
		return "-" + es6NumberToString(-n)
	}

	// Use 'e' format to get the shortest significand and exponent.
	// strconv.FormatFloat with 'e' and prec=-1 gives the shortest
	// representation in scientific notation: d.dddde±dd
	s := strconv.FormatFloat(n, 'e', -1, 64)

	// Parse the mantissa and exponent from the string.
	eIdx := strings.IndexByte(s, 'e')
	mantissa := s[:eIdx]
	expStr := s[eIdx+1:]
	exp, _ := strconv.Atoi(expStr)

	// Split mantissa into integer and fractional digits.
	// mantissa is either "d" or "d.ddd"
	var digits string
	if dotIdx := strings.IndexByte(mantissa, '.'); dotIdx >= 0 {
		digits = mantissa[:dotIdx] + mantissa[dotIdx+1:]
	} else {
		digits = mantissa
	}

	// k = number of significant digits, e = exponent+1 (position of decimal)
	k := len(digits)
	e := exp + 1 // e is the power such that the value is 0.digits * 10^e

	// ECMAScript rules for choosing notation:
	if e >= 1 && e <= 21 {
		if k <= e {
			// Integer that fits without exponential: append zeros.
			return digits + strings.Repeat("0", e-k)
		}
		// Decimal point within the digits: d.ddd
		return digits[:e] + "." + digits[e:]
	}
	if e >= -5 && e <= 0 {
		// Small number: 0.000ddd
		return "0." + strings.Repeat("0", -e) + digits
	}

	// Exponential notation.
	var mantissaPart string
	if k == 1 {
		mantissaPart = digits
	} else {
		mantissaPart = digits[:1] + "." + digits[1:]
	}
	expVal := e - 1
	if expVal > 0 {
		return mantissaPart + "e+" + strconv.Itoa(expVal)
	}
	return mantissaPart + "e-" + strconv.Itoa(-expVal)
}
