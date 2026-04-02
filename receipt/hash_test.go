package receipt

import (
	"math"
	"strings"
	"testing"
)

func TestSHA256Hash(t *testing.T) {
	hash := SHA256Hash("hello")
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("expected sha256: prefix, got %s", hash)
	}
	// SHA-256 of "hello" is well-known.
	want := "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != want {
		t.Errorf("got %s, want %s", hash, want)
	}
}

func TestCanonicalizeObjectKeyOrder(t *testing.T) {
	// Keys must be sorted lexicographically.
	type obj struct {
		B string `json:"b"`
		A string `json:"a"`
	}
	got, err := Canonicalize(obj{B: "2", A: "1"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"1","b":"2"}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalizeNumbers(t *testing.T) {
	got, err := Canonicalize(map[string]any{"n": 42.0, "f": 1.5})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"f":1.5,"n":42}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestES6NumberToString(t *testing.T) {
	tests := []struct {
		name string
		in   float64
		want string
	}{
		// Negative zero.
		{name: "neg_zero", in: math.Copysign(0, -1), want: "0"},
		// Positive zero.
		{name: "pos_zero", in: 0, want: "0"},
		// Simple integers.
		{in: 1, want: "1"},
		{in: -1, want: "-1"},
		{in: 42, want: "42"},
		{in: 100, want: "100"},
		// Decimals.
		{in: 1.5, want: "1.5"},
		{in: 0.5, want: "0.5"},
		{in: -0.5, want: "-0.5"},
		{in: 3.14159, want: "3.14159"},
		// Small numbers (0.0...0ddd range, e in [-5, 0]).
		{in: 0.1, want: "0.1"},
		{in: 0.01, want: "0.01"},
		{in: 0.001, want: "0.001"},
		{in: 0.0001, want: "0.0001"},
		{in: 0.00001, want: "0.00001"},
		{in: 0.000001, want: "0.000001"},
		// Very small numbers — exponential notation.
		{in: 0.0000001, want: "1e-7"},
		{in: 1e-20, want: "1e-20"},
		{in: 5e-7, want: "5e-7"},
		{in: 1.5e-8, want: "1.5e-8"},
		// Large integers without exponential (e <= 21).
		{in: 1e20, want: "100000000000000000000"},
		{in: 1e10, want: "10000000000"},
		// Large numbers — exponential notation (e > 21).
		{in: 1e21, want: "1e+21"},
		{in: 1e100, want: "1e+100"},
		{in: 1.5e21, want: "1.5e+21"},
		// Near int64 boundary — must NOT overflow.
		{in: 9.223372036854776e+18, want: "9223372036854776000"},
		{in: 9.9e18, want: "9900000000000000000"},
		{in: 9.9e19, want: "99000000000000000000"},
		// MaxFloat64-scale.
		{in: 1.7976931348623157e+308, want: "1.7976931348623157e+308"},
		// Smallest positive float64.
		{in: 5e-324, want: "5e-324"},
	}

	for _, tt := range tests {
		name := tt.name
		if name == "" {
			name = tt.want
		}
		t.Run(name, func(t *testing.T) {
			got, err := canonicalizeNumber(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("canonicalizeNumber(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeNumberNonFinite(t *testing.T) {
	for _, n := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		_, err := canonicalizeNumber(n)
		if err == nil {
			t.Errorf("expected error for %v", n)
		}
	}
}

func TestCanonicalizeNullAndBool(t *testing.T) {
	got, err := Canonicalize(map[string]any{"a": nil, "b": true, "c": false})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":null,"b":true,"c":false}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestHashReceiptWithNilOptionalFields(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// Receipt with nil Intent, nil Authorization, nil ActionTarget.
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow, Target: nil},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
		Intent:    nil,
		Authorization: nil,
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = HashReceipt(signed)
	if err != nil {
		t.Fatalf("HashReceipt with nil optional fields should not error: %v", err)
	}
}

func TestCanonicalizeUnicodeStrings(t *testing.T) {
	obj := map[string]any{
		"\u00e9": "caf\u00e9",
		"key":   "\u2603",
	}
	got, err := Canonicalize(obj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Keys sorted: "key" < "\u00e9" (by Unicode code point).
	want := `{"key":"☃","é":"café"}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalizeDeeplyNested(t *testing.T) {
	// Build 6 levels of nesting.
	inner := map[string]any{"leaf": true}
	for i := 0; i < 5; i++ {
		inner = map[string]any{"level": inner}
	}
	_, err := Canonicalize(inner)
	if err != nil {
		t.Fatalf("deeply nested canonicalization should not error: %v", err)
	}
}

func TestHashReceiptDeterministic(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:test"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})
	signed, err := Sign(unsigned, kp.PrivateKey, "did:agent:test#key-1")
	if err != nil {
		t.Fatal(err)
	}

	h1, err := HashReceipt(signed)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashReceipt(signed)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("hashes differ: %s vs %s", h1, h2)
	}
}
