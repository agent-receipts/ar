package emitter

import (
	"strconv"
	"testing"
)

// TestDaemonProtocolRangeWellFormed guards the range invariant: min <= max.
func TestDaemonProtocolRangeWellFormed(t *testing.T) {
	if DaemonProtocolMin > DaemonProtocolMax {
		t.Fatalf("declared daemon-protocol range is inverted: min %d > max %d",
			DaemonProtocolMin, DaemonProtocolMax)
	}
}

// TestDaemonProtocolRangeCoversEmittedVersion ties the declared range to the
// version the SDK actually stamps on the wire. SupportedFrameVersion must parse
// to an integer inside [min, max]; otherwise the SDK would advertise a range
// that does not match the frames it emits, defeating Gate #8. While the SDK
// emits a single version, min == max == that version.
func TestDaemonProtocolRangeCoversEmittedVersion(t *testing.T) {
	v, err := strconv.Atoi(SupportedFrameVersion)
	if err != nil {
		t.Fatalf("SupportedFrameVersion %q is not an integer: %v", SupportedFrameVersion, err)
	}
	if v < DaemonProtocolMin || v > DaemonProtocolMax {
		t.Fatalf("SupportedFrameVersion %d is outside declared range [%d, %d]",
			v, DaemonProtocolMin, DaemonProtocolMax)
	}
	if DaemonProtocolMin != v {
		t.Fatalf("SDK emits only %q but advertises min %d", SupportedFrameVersion, DaemonProtocolMin)
	}
	if DaemonProtocolMax != v {
		t.Fatalf("SDK emits only %q but advertises max %d", SupportedFrameVersion, DaemonProtocolMax)
	}
}
