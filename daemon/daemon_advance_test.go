package daemon

import "testing"

func TestAdvanceChainID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Plain ID: append -2.
		{"default", "default-2"},
		{"foo", "foo-2"},
		// Counter increment.
		{"foo-2", "foo-3"},
		{"foo-9", "foo-10"},
		// Date IDs: day component has a leading zero — must not be treated as counter.
		{"2026-06-03", "2026-06-03-2"},
		{"2026-06-03-2", "2026-06-03-3"},
		{"2026-06-03-9", "2026-06-03-10"},
		// Year and month components are always 4 and 2 digits; safe to verify
		// they are not mistaken for counters either.
		{"2026-06", "2026-06-2"},
		// IDs with hyphens in the base but no numeric suffix.
		{"my-chain", "my-chain-2"},
		{"my-chain-2", "my-chain-3"},
		// Leading-zero suffix is not a counter.
		{"chain-01", "chain-01-2"},
		{"chain-00", "chain-00-2"},
	}
	for _, tc := range cases {
		got := advanceChainID(tc.in)
		if got != tc.want {
			t.Errorf("advanceChainID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
