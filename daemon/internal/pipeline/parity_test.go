package pipeline

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestEmitterFrameParityKnownFields asserts that EmitterFrame's JSON tags
// exactly match the expected list. The expected list is the contract:
// updating it forces a deliberate review of the wire format change.
//
// EmitterFrame mirrors sdk/go/emitter.frame field-for-field, plus the
// extra "action_type" field that the daemon reads but the emitter omits.
// A divergence here means a daemon that reads fields the emitter never
// writes, or vice versa.
func TestEmitterFrameParityKnownFields(t *testing.T) {
	expected := []string{
		"action_type", // EmitterFrame-only: taxonomic action type resolved by emitter
		"agent_id",
		"agent_type",
		"channel",
		"correlation_id",
		"decision",
		"drop_count",
		"error",
		"idempotency_key",
		"input",
		"issuer_model",
		"issuer_name",
		"operator_id",
		"operator_name",
		"output",
		"session_id",
		"tool",
		"ts_emit",
		"v",
	}

	got := jsonTagsOfEmitterFrame()
	sort.Strings(got)
	sort.Strings(expected)

	if !reflect.DeepEqual(got, expected) {
		t.Errorf("EmitterFrame JSON tags do not match expected set\n  got:  %v\n  want: %v", got, expected)
	}
}

func jsonTagsOfEmitterFrame() []string {
	t := reflect.TypeOf(EmitterFrame{})
	var tags []string
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			tags = append(tags, name)
		}
	}
	return tags
}
