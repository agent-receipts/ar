package receipt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// productionEnvVar marks a production deployment. GeneratingKeyProvider refuses
// to run when it is set to the exact value "true" (see ADR-0018 § Key
// generation policy and ADR-0019 § S2).
const productionEnvVar = "AGENTRECEIPTS_PRODUCTION"

// devWarning is the one-line, dev-only warning emitted at most once per process
// when a GeneratingKeyProvider is constructed outside production.
const devWarning = "⚠ GeneratingKeyProvider is dev-only — set AGENTRECEIPTS_PRODUCTION=true to disable in production\n"

// ErrProductionKeyProvider is returned by NewGeneratingKeyProvider when it is
// constructed in a production deployment (AGENTRECEIPTS_PRODUCTION=true).
//
// Generating a keypair on the fly mints a fresh DID on every cold start,
// producing an unverifiable audit trail with no error surfaced. Production
// deployments must provision a keypair out-of-band and load it via a file,
// env-var, or secret-store key provider. See the ephemeral-compute deployment
// guide.
var ErrProductionKeyProvider = errors.New(
	"GeneratingKeyProvider is disabled in production (AGENTRECEIPTS_PRODUCTION=true): " +
		"provision a keypair out-of-band and load it via a file, env-var, or secret-store key provider",
)

// KeyProvider supplies the Ed25519 keypair the SDK signs with. It models
// environments where the private key bytes are accessible locally (files,
// env vars, in-memory fixtures). Environments where the private key is never
// extractable (KMS, HSM, TPM) implement Signer instead (see ADR-0018).
type KeyProvider interface {
	GetKeyPair() (KeyPair, error)
}

// devWarnOnce guarantees the dev-only warning is written at most once per
// process, regardless of how many GeneratingKeyProviders are constructed.
var devWarnOnce sync.Once

// warnWriter is the sink for the dev-only warning. It defaults to os.Stderr
// and is only reassigned by tests.
var warnWriter io.Writer = os.Stderr

// GeneratingKeyProvider generates a fresh Ed25519 keypair for development and
// bootstrap use only. The keypair is stable for the lifetime of the provider.
//
// It is explicitly prohibited in production: construct one when
// AGENTRECEIPTS_PRODUCTION=true and NewGeneratingKeyProvider returns
// ErrProductionKeyProvider before any key is generated.
type GeneratingKeyProvider struct {
	keyPair KeyPair
}

// NewGeneratingKeyProvider generates a fresh keypair for dev/bootstrap use.
//
// It returns ErrProductionKeyProvider if AGENTRECEIPTS_PRODUCTION=true. In all
// other cases it emits a one-time stderr warning that the provider is dev-only
// and returns a provider holding a freshly generated keypair.
func NewGeneratingKeyProvider() (*GeneratingKeyProvider, error) {
	if os.Getenv(productionEnvVar) == "true" {
		return nil, ErrProductionKeyProvider
	}

	devWarnOnce.Do(func() {
		_, _ = io.WriteString(warnWriter, devWarning)
	})

	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &GeneratingKeyProvider{keyPair: kp}, nil
}

// GetKeyPair returns the keypair generated when the provider was constructed.
func (g *GeneratingKeyProvider) GetKeyPair() (KeyPair, error) {
	return g.keyPair, nil
}
