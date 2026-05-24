package aws

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const testKeyID = "arn:aws:kms:us-east-1:111122223333:key/test-ed25519"

// mockKMS is a hand-written KMSClient. Unset hooks fall back to a default
// behaviour backed by an in-test Ed25519 key, so a signature produced by Sign
// verifies against the key returned by GetPublicKey.
type mockKMS struct {
	signHook   func(*kms.SignInput) (*kms.SignOutput, error)
	getPubHook func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)

	mu         sync.Mutex // guards signInputs and getPubCall for concurrent callers
	signInputs []*kms.SignInput
	getPubCall int

	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newMockKMS(t *testing.T) *mockKMS {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return &mockKMS{priv: priv, pub: pub}
}

func (m *mockKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.mu.Lock()
	m.signInputs = append(m.signInputs, in)
	m.mu.Unlock()
	if m.signHook != nil {
		return m.signHook(in)
	}
	sig := ed25519.Sign(m.priv, in.Message)
	return &kms.SignOutput{Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
}

func (m *mockKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	m.mu.Lock()
	m.getPubCall++
	m.mu.Unlock()
	if m.getPubHook != nil {
		return m.getPubHook(in)
	}
	der, err := x509.MarshalPKIXPublicKey(m.pub)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: types.KeySpecEccNistEdwards25519}, nil
}

func newTestSigner(t *testing.T, m *mockKMS) *KMSSigner {
	t.Helper()
	s, err := NewKMSSigner(context.Background(), testKeyID, WithClient(m))
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}
	return s
}

func TestNewKMSSignerEmptyKeyID(t *testing.T) {
	if _, err := NewKMSSigner(context.Background(), "", WithClient(newMockKMS(t))); err == nil {
		t.Fatal("expected error for empty keyID, got nil")
	}
}

func TestNewKMSSignerRejectsNegativeTimeout(t *testing.T) {
	_, err := NewKMSSigner(context.Background(), testKeyID, WithClient(newMockKMS(t)), WithTimeout(-time.Second))
	if err == nil {
		t.Fatal("expected error for negative timeout, got nil")
	}
}

func TestSignSuccess(t *testing.T) {
	m := newMockKMS(t)
	s := newTestSigner(t, m)

	msg := []byte("canonical receipt bytes")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(m.pub, msg, sig) {
		t.Fatal("signature returned by KMSSigner does not verify against the KMS public key")
	}
}

func TestSignPassesEd25519AlgorithmAndRawMessageType(t *testing.T) {
	m := newMockKMS(t)
	s := newTestSigner(t, m)

	if _, err := s.Sign([]byte("msg")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(m.signInputs) != 1 {
		t.Fatalf("expected 1 Sign call, got %d", len(m.signInputs))
	}
	in := m.signInputs[0]
	if in.SigningAlgorithm != types.SigningAlgorithmSpecEd25519Sha512 {
		t.Errorf("SigningAlgorithm = %q, want %q", in.SigningAlgorithm, types.SigningAlgorithmSpecEd25519Sha512)
	}
	if in.MessageType != types.MessageTypeRaw {
		t.Errorf("MessageType = %q, want %q", in.MessageType, types.MessageTypeRaw)
	}
	if in.KeyId == nil || *in.KeyId != testKeyID {
		t.Errorf("KeyId = %v, want %q", in.KeyId, testKeyID)
	}
}

func TestSignErrorPassThrough(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized")
	m := newMockKMS(t)
	m.signHook = func(*kms.SignInput) (*kms.SignOutput, error) { return nil, sentinel }
	s := newTestSigner(t, m)

	_, err := s.Sign([]byte("msg"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Sign error = %v, want it to wrap/return %v", err, sentinel)
	}
}

func TestGetPublicKeySuccess(t *testing.T) {
	m := newMockKMS(t)
	s := newTestSigner(t, m)

	got, err := s.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(got), ed25519.PublicKeySize)
	}
	if !bytes.Equal(got, m.pub) {
		t.Fatal("returned public key does not match the KMS key")
	}
}

func TestGetPublicKeyCachedAfterFirstCall(t *testing.T) {
	m := newMockKMS(t)
	s := newTestSigner(t, m)

	first, err := s.GetPublicKey()
	if err != nil {
		t.Fatalf("first GetPublicKey: %v", err)
	}
	second, err := s.GetPublicKey()
	if err != nil {
		t.Fatalf("second GetPublicKey: %v", err)
	}
	if m.getPubCall != 1 {
		t.Fatalf("expected exactly 1 kms:GetPublicKey call, got %d", m.getPubCall)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("cached public key differs from first result")
	}
}

// Mutating the slice returned by GetPublicKey must not corrupt the cached key
// other callers see.
func TestGetPublicKeyReturnsCopy(t *testing.T) {
	m := newMockKMS(t)
	s := newTestSigner(t, m)

	first, err := s.GetPublicKey()
	if err != nil {
		t.Fatalf("first GetPublicKey: %v", err)
	}
	for i := range first {
		first[i] ^= 0xff // scribble over the returned slice
	}

	second, err := s.GetPublicKey()
	if err != nil {
		t.Fatalf("second GetPublicKey: %v", err)
	}
	if !bytes.Equal(second, m.pub) {
		t.Fatal("cache was corrupted by mutation of a previously returned slice")
	}
}

func TestGetPublicKeyErrorPassThrough(t *testing.T) {
	sentinel := errors.New("NotFoundException: key does not exist")
	m := newMockKMS(t)
	m.getPubHook = func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) { return nil, sentinel }
	s := newTestSigner(t, m)

	if _, err := s.GetPublicKey(); !errors.Is(err, sentinel) {
		t.Fatalf("GetPublicKey error = %v, want it to wrap/return %v", err, sentinel)
	}
}

// A failed fetch must not poison the cache: a later call should retry and can
// succeed. This guards the "cache only success" contract.
func TestGetPublicKeyRetriesAfterError(t *testing.T) {
	m := newMockKMS(t)
	calls := 0
	m.getPubHook = func(in *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("Throttlingexception")
		}
		der, err := x509.MarshalPKIXPublicKey(m.pub)
		if err != nil {
			return nil, err
		}
		return &kms.GetPublicKeyOutput{PublicKey: der}, nil
	}
	s := newTestSigner(t, m)

	if _, err := s.GetPublicKey(); err == nil {
		t.Fatal("expected first GetPublicKey to fail")
	}
	got, err := s.GetPublicKey()
	if err != nil {
		t.Fatalf("second GetPublicKey: %v", err)
	}
	if !bytes.Equal(got, m.pub) {
		t.Fatal("retried public key does not match")
	}
}

func TestGetPublicKeyRejectsNonEd25519(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa pubkey: %v", err)
	}
	m := newMockKMS(t)
	m.getPubHook = func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
		return &kms.GetPublicKeyOutput{PublicKey: der}, nil
	}
	s := newTestSigner(t, m)

	if _, err := s.GetPublicKey(); err == nil {
		t.Fatal("expected error for non-Ed25519 key, got nil")
	}
}

// KMSSigner is documented as safe for concurrent use. Run many goroutines that
// mix Sign and first-time GetPublicKey; under -race this exercises the mutex,
// and the public key must still be fetched from KMS exactly once.
func TestConcurrentUseFetchesPublicKeyOnce(t *testing.T) {
	m := newMockKMS(t)
	s := newTestSigner(t, m)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if _, err := s.Sign([]byte("msg")); err != nil {
				errs <- err
				return
			}
			got, err := s.GetPublicKey()
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, m.pub) {
				errs <- errors.New("public key mismatch")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent call failed: %v", err)
	}

	m.mu.Lock()
	calls := m.getPubCall
	m.mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected exactly 1 kms:GetPublicKey call across goroutines, got %d", calls)
	}
}
