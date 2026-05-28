//go:build linux || darwin

// Data-driven conformance runner for the shared emit failure contract vector
// (cross-sdk-tests/emit_failure_vectors.json, ADR-0025). The vector — not this
// file — is the single source of truth for which cases exist: the runner fails
// on any case name it does not handle, so adding a case to the JSON breaks this
// SDK until it is implemented here.
package emitter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const emitFailureVectorsPath = "../../../cross-sdk-tests/emit_failure_vectors.json"

type emitFailureVectors struct {
	Version int `json:"version"`
	Cases   []struct {
		Name   string `json:"name"`
		Expect string `json:"expect"`
	} `json:"cases"`
}

// classifyEmitOutcome maps an Emit result to one of the vector's outcome
// categories. Transport failures are tagged with ErrTransport (ADR-0025), so
// they are distinguishable from caller-bug errors without string matching.
func classifyEmitOutcome(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, ErrTransport):
		return "transport_error"
	default:
		return "caller_error"
	}
}

func TestEmitFailureContractVectors(t *testing.T) {
	data, err := os.ReadFile(emitFailureVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", emitFailureVectorsPath, err)
	}
	var vectors emitFailureVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("unmarshal %s: %v", emitFailureVectorsPath, err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("emit_failure_vectors.json has no cases")
	}

	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			// Default mode (no WithBestEffort) against a socket with no listener.
			missing := filepath.Join(shortSocketDir(t), "missing.sock")
			em, err := NewDaemon(
				WithSocketPath(missing),
				WithLogger(silentLogger()),
			)
			if err != nil {
				t.Fatalf("NewDaemon: %v", err)
			}
			defer em.Close()

			ev := Event{Channel: "mcp", Tool: Tool{Name: "noop"}, Decision: "allowed"}
			switch c.Name {
			case "dial_failure_unreachable_socket":
				// well-formed event, left as-is
			case "caller_bug_invalid_decision":
				ev.Decision = "bogus"
			default:
				t.Fatalf("unhandled emit-failure case %q: implement it or remove it from the vector", c.Name)
			}

			got := classifyEmitOutcome(em.Emit(context.Background(), ev))
			if got != c.Expect {
				t.Errorf("case %q: outcome = %q; want %q", c.Name, got, c.Expect)
			}
		})
	}
}
