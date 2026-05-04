// Package keysource defines the interface the daemon uses to sign receipts.
// The shape (Sign / PublicKey / Rotate / Init / Teardown) matches ADR-0015
// so PKCS#11 and cloud-KMS adapters land later as new types implementing this
// interface, not as a redesign of the daemon's signing path.
//
// Phase 1 ships only the file-backed adapter (file.go).
package keysource

import "errors"

// ErrNotImplemented is returned by adapters that do not yet support an
// optional operation (typically Rotate on the file-backed adapter).
var ErrNotImplemented = errors.New("keysource: operation not implemented")

// KeySource signs canonical receipt bytes and exposes the matching public key.
// Implementations MUST be safe for concurrent use; the daemon signs from many
// goroutines.
type KeySource interface {
	// Init loads or wires up key material. Called once at daemon startup.
	// Implementations MUST fail loudly when keys are missing or malformed —
	// silently signing with a default-generated key would defeat the audit
	// property.
	Init() error

	// Sign returns the Ed25519 signature over message. The signature is the
	// raw 64-byte form; the caller multibase-encodes it.
	Sign(message []byte) ([]byte, error)

	// PublicKey returns the PEM-encoded SPKI public key for verifiers.
	PublicKey() (string, error)

	// VerificationMethod returns the DID URL or other reference verifiers use
	// to look up the public key. Daemon embeds this in proof.verificationMethod.
	VerificationMethod() string

	// Rotate generates or installs a new key, retaining the public-key
	// receipts pre-rotation can still be verified against. ADR-0015 owns the
	// detailed semantics; Phase 1 returns ErrNotImplemented.
	Rotate() error

	// Teardown wipes any in-memory key material. Called on graceful daemon
	// shutdown.
	Teardown() error
}
