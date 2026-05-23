// Package aws provides AWS-backed implementations of the Agent Receipts Go
// SDK signing abstraction (ADR-0018). It ships as a separate Go module so
// that the core sdk/go package keeps zero AWS dependencies — projects that
// never import this module never pull the AWS SDK into their dependency
// closure.
//
// The headline type is KMSSigner: an Ed25519 Signer whose private key never
// leaves AWS KMS. Signature operations are delegated to the kms:Sign API and
// the public key is fetched once via kms:GetPublicKey and cached for the
// signer's lifetime.
package aws

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Signer is the Agent Receipts signing abstraction from ADR-0018, expressed in
// Go. Implementations sign canonical receipt bytes without ever exposing the
// private key. GetPublicKey returns the raw 32-byte Ed25519 public key (RFC
// 8032 §5.1.5) used by verifiers.
//
// The core sdk/go package does not yet define this interface; it is declared
// here so adapters in this module satisfy a single, documented contract.
type Signer interface {
	Sign(message []byte) ([]byte, error)
	GetPublicKey() ([]byte, error)
}

// KMSClient is the subset of the AWS KMS API that KMSSigner depends on. The
// concrete *kms.Client satisfies it; tests inject a mock. It is deliberately
// narrow so the dependency surface — and the mock — stay small.
type KMSClient interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KMSSigner signs Agent Receipts with an Ed25519 KMS key. The private key
// never leaves KMS; this type holds only the key identifier, a KMS client, and
// a cached copy of the public key. It is safe for concurrent use.
type KMSSigner struct {
	keyID   string
	client  KMSClient
	baseCtx context.Context
	timeout time.Duration

	mu     sync.Mutex
	pubKey []byte // raw 32-byte Ed25519 public key; nil until first fetch
}

var _ Signer = (*KMSSigner)(nil)

type options struct {
	client  KMSClient
	timeout time.Duration
}

// Option configures a KMSSigner.
type Option func(*options)

// WithClient injects a custom KMS client. The primary use is testing with a
// mock; production code omits it and lets NewKMSSigner build a client from the
// ambient AWS credential chain.
func WithClient(c KMSClient) Option {
	return func(o *options) { o.client = c }
}

// WithTimeout applies a per-request deadline to each kms:Sign and
// kms:GetPublicKey call, derived from the context passed to NewKMSSigner. The
// ADR-0018 Signer interface takes no per-call context, so this is how callers
// bound individual request latency. Zero (the default) applies no deadline of
// its own and relies on aws-sdk-go-v2's built-in timeouts and retries.
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// NewKMSSigner constructs a KMSSigner for the given KMS key.
//
// keyID is a key ID, key ARN, alias name, or alias ARN — passed through to AWS
// unchanged (see the kms:Sign KeyId docs for the accepted forms). The key must
// be an ECC_NIST_EDWARDS25519 (Ed25519) key with SIGN_VERIFY usage.
//
// ctx governs credential resolution here and, for the signer's lifetime, every
// subsequent Sign and GetPublicKey request. Pass a long-lived context (for
// example context.Background()) for a long-lived signer and use WithTimeout to
// bound individual requests. Credentials come from the ambient AWS SDK
// credential chain (instance role, IRSA, environment, shared profile); this
// adapter never accepts static credentials.
func NewKMSSigner(ctx context.Context, keyID string, opts ...Option) (*KMSSigner, error) {
	if keyID == "" {
		return nil, errors.New("kms signer: keyID must not be empty")
	}

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	client := o.client
	if client == nil {
		cfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("kms signer: load AWS config: %w", err)
		}
		client = kms.NewFromConfig(cfg)
	}

	return &KMSSigner{
		keyID:   keyID,
		client:  client,
		baseCtx: ctx,
		timeout: o.timeout,
	}, nil
}

// Sign returns the raw Ed25519 signature over message, computed inside KMS.
//
// It calls kms:Sign with SigningAlgorithm=ED25519_SHA_512 and MessageType=RAW,
// which is standard (pure) Ed25519 per RFC 8032: KMS performs the SHA-512 hash
// internally, so the signature verifies with crypto/ed25519.Verify against the
// public key from GetPublicKey. Any AWS SDK error is returned verbatim so
// callers can distinguish throttling, access-denied, and key-not-found.
func (s *KMSSigner) Sign(message []byte) ([]byte, error) {
	ctx, cancel := s.requestContext()
	defer cancel()

	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          message,
		SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512,
		MessageType:      types.MessageTypeRaw,
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil
}

// GetPublicKey returns the raw 32-byte Ed25519 public key (RFC 8032 §5.1.5).
//
// The first call fetches the key via kms:GetPublicKey, decodes the DER-encoded
// SPKI that KMS returns, and caches the raw bytes. Subsequent calls return the
// cached value without contacting AWS. A failed fetch is not cached, so a
// later call retries. AWS SDK errors are returned verbatim.
func (s *KMSSigner) GetPublicKey() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pubKey != nil {
		return s.pubKey, nil
	}

	ctx, cancel := s.requestContext()
	defer cancel()

	out, err := s.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(s.keyID),
	})
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms signer: parse SPKI public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("kms signer: key %s is not Ed25519 (got %T); use an ECC_NIST_EDWARDS25519 KMS key", s.keyID, pub)
	}

	s.pubKey = edPub
	return s.pubKey, nil
}

// requestContext derives the context for a single AWS request from the
// signer's base context, applying the configured per-request timeout if set.
// The returned cancel func is always non-nil and safe to defer.
func (s *KMSSigner) requestContext() (context.Context, context.CancelFunc) {
	if s.timeout > 0 {
		return context.WithTimeout(s.baseCtx, s.timeout)
	}
	return context.WithCancel(s.baseCtx)
}
