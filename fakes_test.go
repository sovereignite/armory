// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package armory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/sovereignite/anchor"
)

type fakeObject struct {
	public anchor.Public
	signer crypto.Signer
}

type fakeBackend struct {
	mu sync.Mutex

	supported map[anchor.Algorithm]bool
	objects   map[anchor.Handle]fakeObject

	createCalls  int
	signCalls    int
	evictCalls   int
	signRequests []anchor.SignRequest

	evictFailures        int
	createResponseLosses int
	afterPrepare         func()
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		supported: map[anchor.Algorithm]bool{
			anchor.AlgorithmRSA4096:   true,
			anchor.AlgorithmECDSAP256: true,
			anchor.AlgorithmEd25519:   true,
		},
		objects: make(map[anchor.Handle]fakeObject),
	}
}

func (f *fakeBackend) Supports(
	ctx context.Context,
	algorithm anchor.Algorithm,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.supported[algorithm] {
		return &anchor.UnsupportedCapabilityError{
			Algorithm: algorithm,
			Reason:    "fake TPM capability disabled",
		}
	}
	return nil
}

func (f *fakeBackend) CreatePersistent(
	ctx context.Context,
	handle anchor.Handle,
	template anchor.Template,
	prepare anchor.PreparePersistent,
) (anchor.Public, error) {
	if err := ctx.Err(); err != nil {
		return anchor.Public{}, err
	}
	if !handle.IsPersistent() {
		return anchor.Public{}, errors.New("fake TPM received a non-persistent handle")
	}
	if err := f.Supports(ctx, template.Algorithm); err != nil {
		return anchor.Public{}, err
	}
	expected, err := anchor.SigningTemplate(template.Algorithm)
	if err != nil {
		return anchor.Public{}, err
	}
	if template != expected {
		return anchor.Public{}, errors.New("fake TPM received an unexpected template")
	}
	signer, err := generateFakeSigner(template.Algorithm)
	if err != nil {
		return anchor.Public{}, err
	}
	public, err := fakePublic(handle, template, signer.Public())
	if err != nil {
		return anchor.Public{}, err
	}

	f.mu.Lock()
	if _, exists := f.objects[handle]; exists {
		f.mu.Unlock()
		return anchor.Public{}, anchor.ErrHandleOccupied
	}
	f.mu.Unlock()
	if prepare == nil {
		return anchor.Public{}, errors.New("fake TPM requires persistent preparation")
	}
	if err := prepare(public); err != nil {
		return anchor.Public{}, err
	}
	if f.afterPrepare != nil {
		f.afterPrepare()
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.objects[handle]; exists {
		return anchor.Public{}, anchor.ErrHandleOccupied
	}
	f.createCalls++
	f.objects[handle] = fakeObject{public: public, signer: signer}
	if f.createResponseLosses > 0 {
		f.createResponseLosses--
		return anchor.Public{}, errors.New("injected response loss after persistence")
	}
	return cloneTPMPublic(public)
}

func (f *fakeBackend) ReadPublic(
	ctx context.Context,
	handle anchor.Handle,
) (anchor.Public, error) {
	if err := ctx.Err(); err != nil {
		return anchor.Public{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	object, exists := f.objects[handle]
	if !exists {
		return anchor.Public{}, anchor.ErrHandleNotFound
	}
	return cloneTPMPublic(object.public)
}

func (f *fakeBackend) Sign(
	ctx context.Context,
	request anchor.SignRequest,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	object, exists := f.objects[request.Object.Handle]
	if !exists {
		f.mu.Unlock()
		return nil, anchor.ErrHandleNotFound
	}
	if subtle.ConstantTimeCompare(request.Object.Name, object.public.Name) != 1 ||
		request.Object.Template != object.public.Template {
		f.mu.Unlock()
		return nil, ErrMetadataMismatch
	}
	if request.Purpose != anchor.SignPurposeCertificate ||
		request.Scheme != object.public.Template.SigningScheme {
		f.mu.Unlock()
		return nil, errors.New("fake TPM rejected signing purpose or scheme")
	}
	if request.Hash != crypto.Hash(0) && !request.Hash.Available() {
		f.mu.Unlock()
		return nil, errors.New("fake TPM received unavailable hash")
	}
	f.signCalls++
	f.signRequests = append(f.signRequests, cloneSignRequest(request))
	signer := object.signer
	f.mu.Unlock()

	var options crypto.SignerOpts = request.Hash
	return signer.Sign(rand.Reader, request.Payload, options)
}

func (f *fakeBackend) EvictPersistent(
	ctx context.Context,
	reference anchor.ObjectReference,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	object, exists := f.objects[reference.Handle]
	if !exists {
		return anchor.ErrHandleNotFound
	}
	if subtle.ConstantTimeCompare(reference.Name, object.public.Name) != 1 ||
		reference.Template != object.public.Template {
		return ErrMetadataMismatch
	}
	f.evictCalls++
	if f.evictFailures > 0 {
		f.evictFailures--
		return errors.New("injected fake TPM eviction failure")
	}
	delete(f.objects, reference.Handle)
	return nil
}

func (f *fakeBackend) Close() error {
	return nil
}

func (f *fakeBackend) replaceName(handle anchor.Handle, name []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	object := f.objects[handle]
	object.public.Name = slices.Clone(name)
	f.objects[handle] = object
}

func (f *fakeBackend) deleteHandle(handle anchor.Handle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, handle)
}

func (f *fakeBackend) hasHandle(handle anchor.Handle) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, exists := f.objects[handle]
	return exists
}

func generateFakeSigner(algorithm anchor.Algorithm) (crypto.Signer, error) {
	switch algorithm {
	case anchor.AlgorithmRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case anchor.AlgorithmECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case anchor.AlgorithmEd25519:
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		return privateKey, err
	default:
		return nil, &anchor.UnsupportedCapabilityError{
			Algorithm: algorithm,
			Reason:    "fake signer algorithm is unknown",
		}
	}
}

func fakePublic(
	handle anchor.Handle,
	template anchor.Template,
	key crypto.PublicKey,
) (anchor.Public, error) {
	public := anchor.Public{
		Handle:    handle,
		Template:  template,
		PublicKey: key,
		Name:      []byte{1},
	}
	der, err := anchor.CanonicalPublicKey(public)
	if err != nil {
		return anchor.Public{}, err
	}
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return anchor.Public{}, err
	}
	hash := sha256.New()
	if _, err := hash.Write(templateJSON); err != nil {
		return anchor.Public{}, err
	}
	if _, err := hash.Write(der); err != nil {
		return anchor.Public{}, err
	}
	var handleBytes [4]byte
	binary.BigEndian.PutUint32(handleBytes[:], uint32(handle))
	if _, err := hash.Write(handleBytes[:]); err != nil {
		return anchor.Public{}, err
	}
	public.Name = hash.Sum(nil)
	return public, nil
}

func cloneTPMPublic(public anchor.Public) (anchor.Public, error) {
	cloned := public
	cloned.Name = slices.Clone(public.Name)
	der, err := x509.MarshalPKIXPublicKey(public.PublicKey)
	if err != nil {
		return anchor.Public{}, err
	}
	cloned.PublicKey, err = x509.ParsePKIXPublicKey(der)
	if err != nil {
		return anchor.Public{}, err
	}
	return cloned, nil
}

func cloneSignRequest(request anchor.SignRequest) anchor.SignRequest {
	request.Object.Name = slices.Clone(request.Object.Name)
	request.Payload = slices.Clone(request.Payload)
	return request
}

type memoryStore struct {
	mu            sync.Mutex
	operationLock chan struct{}

	snapshot        Snapshot
	saveCalls       int
	failSaveAt      int
	uncertainSaveAt int
}

func newMemoryStore() *memoryStore {
	store := &memoryStore{
		snapshot:      emptySnapshot(),
		operationLock: make(chan struct{}, 1),
	}
	store.operationLock <- struct{}{}
	return store
}

func (s *memoryStore) Load() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSnapshot(s.snapshot), nil
}

func (s *memoryStore) Save(snapshot Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveCalls++
	if s.failSaveAt > 0 && s.saveCalls == s.failSaveAt {
		return errors.New("injected metadata save failure")
	}
	if s.snapshot.Revision == math.MaxUint64 ||
		snapshot.Revision != s.snapshot.Revision+1 {
		return fmt.Errorf(
			"%w: current revision %d, replacement revision %d",
			ErrMetadataRevisionConflict,
			s.snapshot.Revision,
			snapshot.Revision,
		)
	}
	s.snapshot = cloneSnapshot(snapshot)
	if s.uncertainSaveAt > 0 && s.saveCalls == s.uncertainSaveAt {
		return errors.Join(
			ErrMetadataDurabilityUncertain,
			errors.New("injected post-replacement sync failure"),
		)
	}
	return nil
}

func (s *memoryStore) withExclusive(
	ctx context.Context,
	operation func(Store) error,
) error {
	if operation == nil {
		return errors.New("metadata transaction operation is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.operationLock:
	}
	defer func() {
		s.operationLock <- struct{}{}
	}()
	return operation(s)
}

func (s *memoryStore) mutate(mutate func(*Snapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mutate(&s.snapshot)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func caPolicy(
	role Role,
	algorithm anchor.Algorithm,
	handles ...anchor.Handle,
) RolePolicy {
	return RolePolicy{
		Role:             role,
		Purpose:          PurposeCertificateAuthority,
		Algorithm:        algorithm,
		Handles:          handles,
		RotationInterval: 24 * time.Hour,
	}
}

func identityPolicy(
	algorithm anchor.Algorithm,
	handles ...anchor.Handle,
) RolePolicy {
	return RolePolicy{
		Role:      RoleDeviceIPNSIdentity,
		Purpose:   PurposeDeviceIPNSIdentity,
		Algorithm: algorithm,
		Handles:   handles,
		Lifetime:  true,
	}
}

func publicKeyFromMetadata(metadata KeyMetadata) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(metadata.PublicKeyDER)
}

func assertNoPrivateMaterial(t testingT, snapshot Snapshot, canary []byte) {
	t.Helper()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, canary) {
		t.Fatalf("public metadata contains private canary %q", canary)
	}
	for _, forbidden := range [][]byte{
		[]byte(`"private"`),
		[]byte(`"seed"`),
		[]byte(`"auth_value"`),
	} {
		if bytes.Contains(bytes.ToLower(encoded), forbidden) {
			t.Fatalf("public metadata contains forbidden field %q", forbidden)
		}
	}
}

type testingT interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

var (
	_ anchor.Backend = (*fakeBackend)(nil)
	_ Store       = (*memoryStore)(nil)
	_ Clock       = (*fakeClock)(nil)
)
