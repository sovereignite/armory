// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package armory

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sovereignite/anchor"
)

func TestEnsureRoleSupportsAllRequestedAlgorithms(t *testing.T) {
	testCases := []struct {
		name      string
		role      Role
		algorithm anchor.Algorithm
		assertKey func(*testing.T, any)
	}{
		{
			name:      "RSA-4096",
			role:      "rsa-ca",
			algorithm: anchor.AlgorithmRSA4096,
			assertKey: func(t *testing.T, key any) {
				t.Helper()
				publicKey, ok := key.(*rsa.PublicKey)
				if !ok || publicKey.N.BitLen() != 4096 {
					t.Fatalf("public key = %T, want RSA-4096", key)
				}
			},
		},
		{
			name:      "ECDSA-P256",
			role:      "ecdsa-ca",
			algorithm: anchor.AlgorithmECDSAP256,
			assertKey: func(t *testing.T, key any) {
				t.Helper()
				publicKey, ok := key.(*ecdsa.PublicKey)
				if !ok || publicKey.Curve.Params().Name != "P-256" {
					t.Fatalf("public key = %T, want ECDSA P-256", key)
				}
			},
		},
		{
			name:      "Ed25519",
			role:      "ed25519-ca",
			algorithm: anchor.AlgorithmEd25519,
			assertKey: func(t *testing.T, key any) {
				t.Helper()
				publicKey, ok := key.(ed25519.PublicKey)
				if !ok || len(publicKey) != ed25519.PublicKeySize {
					t.Fatalf("public key = %T, want Ed25519", key)
				}
			},
		},
	}

	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := newFakeBackend()
			store := newMemoryStore()
			clock := &fakeClock{now: time.Date(
				2026,
				time.January,
				2,
				3,
				4,
				5,
				0,
				time.UTC,
			)}
			firstHandle := anchor.PersistentHandleFirst + anchor.Handle(index*2+1)
			policy := caPolicy(
				testCase.role,
				testCase.algorithm,
				firstHandle,
				firstHandle+1,
			)
			manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := manager.EnsureRole(context.Background(), testCase.role)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Handle != firstHandle || metadata.Generation != 1 {
				t.Fatalf("metadata = %#v, want first handle and generation one", metadata)
			}
			key, err := publicKeyFromMetadata(metadata)
			if err != nil {
				t.Fatal(err)
			}
			testCase.assertKey(t, key)
			snapshot, err := manager.PublicSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			assertNoPrivateMaterial(t, snapshot, []byte("FAKE-PRIVATE-CANARY"))
			if backend.createCalls != 1 {
				t.Fatalf("create calls = %d, want 1", backend.createCalls)
			}
		})
	}
}

func TestUnsupportedCapabilityHasNoFallback(t *testing.T) {
	backend := newFakeBackend()
	backend.supported[anchor.AlgorithmEd25519] = false
	store := newMemoryStore()
	clock := &fakeClock{now: time.Now().UTC()}
	policy := caPolicy(
		"unsupported-ca",
		anchor.AlgorithmEd25519,
		anchor.PersistentHandleFirst+10,
		anchor.PersistentHandleFirst+11,
	)
	manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(
		context.Background(),
		policy.Role,
	); !errors.Is(err, anchor.ErrUnsupportedCapability) {
		t.Fatalf("EnsureRole error = %v, want unsupported capability", err)
	}
	if backend.createCalls != 0 {
		t.Fatalf("create calls = %d, want 0", backend.createCalls)
	}
	if store.saveCalls != 0 {
		t.Fatalf("metadata save calls = %d, want 0", store.saveCalls)
	}
	if len(store.snapshot.Roles) != 0 {
		t.Fatalf("persisted roles = %d, want 0", len(store.snapshot.Roles))
	}
}

func TestInitializeIsIdempotentAndStopsOnUnsupportedRole(t *testing.T) {
	now := time.Now().UTC()
	identityHandle := anchor.PersistentHandleFirst + 12
	caHandle := anchor.PersistentHandleFirst + 14
	policies := []RolePolicy{
		identityPolicy(anchor.AlgorithmEd25519, identityHandle),
		caPolicy(
			RoleDeviceRootCA,
			anchor.AlgorithmECDSAP256,
			caHandle,
			caHandle+1,
		),
	}

	t.Run("idempotent", func(t *testing.T) {
		backend := newFakeBackend()
		manager, err := NewManager(
			backend,
			newMemoryStore(),
			policies,
			nil,
			&fakeClock{now: now},
		)
		if err != nil {
			t.Fatal(err)
		}
		first, err := manager.Initialize(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		second, err := manager.Initialize(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("second initialization = %#v, want %#v", second, first)
		}
		if backend.createCalls != len(policies) {
			t.Fatalf("create calls = %d, want %d", backend.createCalls, len(policies))
		}
	})

	t.Run("unsupported subordinate", func(t *testing.T) {
		backend := newFakeBackend()
		backend.supported[anchor.AlgorithmECDSAP256] = false
		store := newMemoryStore()
		manager, err := NewManager(
			backend,
			store,
			policies,
			nil,
			&fakeClock{now: now},
		)
		if err != nil {
			t.Fatal(err)
		}
		results, err := manager.Initialize(context.Background())
		if !errors.Is(err, anchor.ErrUnsupportedCapability) {
			t.Fatalf("Initialize error = %v, want unsupported capability", err)
		}
		if len(results) != 1 || results[0].Role != RoleDeviceIPNSIdentity {
			t.Fatalf("Initialize results = %#v, want committed identity only", results)
		}
		if len(store.snapshot.Roles) != 1 {
			t.Fatalf("persisted roles = %d, want 1", len(store.snapshot.Roles))
		}
	})
}

func TestReopenVerifiesPublicMetadataWithoutRegeneration(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	clock := &fakeClock{now: time.Now().UTC()}
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		anchor.PersistentHandleFirst+20,
		anchor.PersistentHandleFirst+21,
	)
	first, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := first.EnsureRole(context.Background(), RoleDeviceRootCA)
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	actual, err := reopened.Metadata(context.Background(), RoleDeviceRootCA)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("reopened metadata = %#v, want %#v", actual, expected)
	}
	if backend.createCalls != 1 {
		t.Fatalf("create calls after reopen = %d, want 1", backend.createCalls)
	}
}

func TestReopenFailsClosedOnTamperingOrMissingHandle(t *testing.T) {
	testCases := []struct {
		name   string
		tamper func(*fakeBackend, *memoryStore, KeyMetadata)
	}{
		{
			name: "stored public name",
			tamper: func(_ *fakeBackend, store *memoryStore, metadata KeyMetadata) {
				store.mutate(func(snapshot *Snapshot) {
					state := snapshot.Roles[metadata.Role]
					state.Active.PublicName[0] ^= 0xff
					snapshot.Roles[metadata.Role] = state
				})
			},
		},
		{
			name: "stored public key",
			tamper: func(_ *fakeBackend, store *memoryStore, metadata KeyMetadata) {
				store.mutate(func(snapshot *Snapshot) {
					state := snapshot.Roles[metadata.Role]
					state.Active.PublicKeyDER[0] ^= 0xff
					snapshot.Roles[metadata.Role] = state
				})
			},
		},
		{
			name: "stored template",
			tamper: func(_ *fakeBackend, store *memoryStore, metadata KeyMetadata) {
				store.mutate(func(snapshot *Snapshot) {
					state := snapshot.Roles[metadata.Role]
					state.Active.Template.Attributes.FixedTPM = false
					snapshot.Roles[metadata.Role] = state
				})
			},
		},
		{
			name: "live public name",
			tamper: func(backend *fakeBackend, _ *memoryStore, metadata KeyMetadata) {
				backend.replaceName(metadata.Handle, []byte("replacement-name"))
			},
		},
		{
			name: "missing live handle",
			tamper: func(backend *fakeBackend, _ *memoryStore, metadata KeyMetadata) {
				backend.deleteHandle(metadata.Handle)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := newFakeBackend()
			store := newMemoryStore()
			clock := &fakeClock{now: time.Now().UTC()}
			policy := caPolicy(
				RoleDeviceRootCA,
				anchor.AlgorithmECDSAP256,
				anchor.PersistentHandleFirst+30,
				anchor.PersistentHandleFirst+31,
			)
			manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA)
			if err != nil {
				t.Fatal(err)
			}
			testCase.tamper(backend, store, metadata)

			reopened, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.Open(
				context.Background(),
			); !errors.Is(err, ErrMetadataMismatch) {
				t.Fatalf("Open error = %v, want metadata mismatch", err)
			}
			if backend.createCalls != 1 {
				t.Fatalf("create calls = %d, want no replacement generation", backend.createCalls)
			}
		})
	}
}

func TestRolePoliciesRequireDisjointPersistentHandles(t *testing.T) {
	shared := anchor.PersistentHandleFirst + 40
	_, err := NewManager(
		newFakeBackend(),
		newMemoryStore(),
		[]RolePolicy{
			caPolicy(RoleDeviceRootCA, anchor.AlgorithmECDSAP256, shared, shared+1),
			caPolicy("other-ca", anchor.AlgorithmECDSAP256, shared, shared+2),
		},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err == nil {
		t.Fatal("NewManager accepted a handle shared by two roles")
	}
}

func TestOccupiedInitialHandleIsNeverAdoptedOrOverwritten(t *testing.T) {
	backend := newFakeBackend()
	handle := anchor.PersistentHandleFirst + 50
	template, err := anchor.SigningTemplate(anchor.AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.CreatePersistent(
		context.Background(),
		handle,
		template,
		func(anchor.Public) error { return nil },
	); err != nil {
		t.Fatal(err)
	}
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		handle,
		handle+1,
	)
	manager, err := NewManager(
		backend,
		newMemoryStore(),
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(
		context.Background(),
		RoleDeviceRootCA,
	); !errors.Is(err, anchor.ErrHandleOccupied) {
		t.Fatalf("EnsureRole error = %v, want occupied handle", err)
	}
	if backend.createCalls != 1 {
		t.Fatalf("create calls = %d, want only the preexisting object", backend.createCalls)
	}
}

func TestMetadataSaveFailureRollsBackNewPersistentObject(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	store.failSaveAt = 1
	handle := anchor.PersistentHandleFirst + 60
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		handle,
		handle+1,
	)
	manager, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA); err == nil {
		t.Fatal("EnsureRole succeeded despite metadata save failure")
	}
	if backend.hasHandle(handle) {
		t.Fatalf("new handle %#x survived failed metadata commit", uint32(handle))
	}
	if len(store.snapshot.Roles) != 0 {
		t.Fatal("failed metadata commit changed stored roles")
	}
}

func TestVisibleMetadataReplacementFailureNeverEvictsReferencedObject(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	// The first save records the creation intent. Inject uncertainty into the
	// second save, where the already-persisted TPM object becomes active.
	store.uncertainSaveAt = 2
	handle := anchor.PersistentHandleFirst + 62
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		handle,
		handle+1,
	)
	manager, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA)
	if !errors.Is(err, ErrMetadataDurabilityUncertain) {
		t.Fatalf("EnsureRole error = %v, want uncertain durability", err)
	}
	if metadata.Handle != handle {
		t.Fatalf("returned handle = %#x, want %#x", metadata.Handle, handle)
	}
	if !backend.hasHandle(handle) {
		t.Fatalf("visible metadata references evicted handle %#x", uint32(handle))
	}
	state := store.snapshot.Roles[RoleDeviceRootCA]
	if state.Active.Handle != handle {
		t.Fatalf("stored active handle = %#x, want %#x", state.Active.Handle, handle)
	}
	cached, cachedErr := manager.Metadata(context.Background(), RoleDeviceRootCA)
	if cachedErr != nil {
		t.Fatal(cachedErr)
	}
	if !reflect.DeepEqual(cached, metadata) {
		t.Fatalf("cached metadata = %#v, want %#v", cached, metadata)
	}
}

func TestRotationSchedulerRotatesOnlyDueSubordinateRoles(t *testing.T) {
	start := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: start}
	backend := newFakeBackend()
	store := newMemoryStore()
	identityHandle := anchor.PersistentHandleFirst + 70
	caHandle := anchor.PersistentHandleFirst + 80
	policies := []RolePolicy{
		identityPolicy(anchor.AlgorithmEd25519, identityHandle),
		caPolicy(
			RoleDeviceRootCA,
			anchor.AlgorithmECDSAP256,
			caHandle,
			caHandle+1,
			caHandle+2,
		),
	}
	manager, err := NewManager(backend, store, policies, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceIPNSIdentity); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA); err != nil {
		t.Fatal(err)
	}
	scheduler, err := NewRotationScheduler(manager, time.Minute, clock)
	if err != nil {
		t.Fatal(err)
	}

	clock.Set(start.Add(24*time.Hour - time.Nanosecond))
	results, err := scheduler.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("early rotation results = %#v, want none", results)
	}

	clock.Set(start.Add(24 * time.Hour))
	results, err = scheduler.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 ||
		results[0].Role != RoleDeviceRootCA ||
		results[0].Generation != 2 ||
		results[0].Handle != uint32(caHandle+1) {
		t.Fatalf("rotation results = %#v, want device CA generation two", results)
	}
	if backend.hasHandle(caHandle) {
		t.Fatal("superseded CA handle was not evicted")
	}
	if !backend.hasHandle(caHandle + 1) {
		t.Fatal("rotated CA handle is not active in fake TPM")
	}
	if !backend.hasHandle(identityHandle) {
		t.Fatal("scheduler changed lifetime identity handle")
	}
	if _, err := manager.Rotate(
		context.Background(),
		RoleDeviceIPNSIdentity,
	); !errors.Is(err, ErrLifetimeIdentityRotation) {
		t.Fatalf("identity Rotate error = %v, want lifetime rejection", err)
	}
}

func TestRotationIntentSaveFailureKeepsOldActiveAndDoesNotPersistNew(t *testing.T) {
	start := time.Now().UTC()
	clock := &fakeClock{now: start}
	backend := newFakeBackend()
	store := newMemoryStore()
	firstHandle := anchor.PersistentHandleFirst + 90
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		firstHandle,
		firstHandle+1,
	)
	manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	original, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA)
	if err != nil {
		t.Fatal(err)
	}
	store.failSaveAt = store.saveCalls + 1
	clock.Set(start.Add(24 * time.Hour))
	if _, err := manager.Rotate(context.Background(), RoleDeviceRootCA); err == nil {
		t.Fatal("Rotate succeeded despite activation save failure")
	}
	if !backend.hasHandle(firstHandle) {
		t.Fatal("old active handle was lost")
	}
	if backend.hasHandle(firstHandle + 1) {
		t.Fatal("uncommitted new handle was not rolled back")
	}
	state := store.snapshot.Roles[RoleDeviceRootCA]
	if !reflect.DeepEqual(state.Active, original) || len(state.Retiring) != 0 {
		t.Fatalf("stored state changed on failed activation: %#v", state)
	}
}

func TestPendingCreationRecoversAfterActivationSaveFailure(t *testing.T) {
	start := time.Now().UTC()
	clock := &fakeClock{now: start}
	backend := newFakeBackend()
	store := newMemoryStore()
	firstHandle := anchor.PersistentHandleFirst + 94
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		firstHandle,
		firstHandle+1,
		firstHandle+2,
	)
	manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA); err != nil {
		t.Fatal(err)
	}
	// Rotation first records its creation intent and then attempts activation.
	store.failSaveAt = store.saveCalls + 2
	clock.Set(start.Add(24 * time.Hour))
	pending, err := manager.Rotate(context.Background(), RoleDeviceRootCA)
	if err == nil {
		t.Fatal("Rotate succeeded despite activation save failure")
	}
	if pending.Generation != 2 || pending.Handle != firstHandle+1 {
		t.Fatalf("pending metadata = %#v, want generation two", pending)
	}
	if !backend.hasHandle(firstHandle) || !backend.hasHandle(firstHandle+1) {
		t.Fatal("activation failure did not preserve both recoverable TPM handles")
	}
	if stored, exists := store.snapshot.Pending[RoleDeviceRootCA]; !exists ||
		stored.Handle != firstHandle+1 {
		t.Fatalf("stored pending creation = %#v, exists=%t", stored, exists)
	}
	if store.snapshot.Roles[RoleDeviceRootCA].Active.Handle != firstHandle {
		t.Fatal("failed activation changed the stored active handle")
	}

	reopened, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered := store.snapshot.Roles[RoleDeviceRootCA]
	if recovered.Active.Handle != firstHandle+1 ||
		recovered.Active.Generation != 2 ||
		len(recovered.Retiring) != 0 {
		t.Fatalf("recovered state = %#v, want generation two fully active", recovered)
	}
	if backend.hasHandle(firstHandle) {
		t.Fatal("recovery did not retire the superseded exact-match handle")
	}
	if _, exists := store.snapshot.Pending[RoleDeviceRootCA]; exists {
		t.Fatal("recovery retained completed creation intent")
	}
}

func TestPendingCreationRecoversLostPersistenceResponse(t *testing.T) {
	backend := newFakeBackend()
	backend.createResponseLosses = 1
	store := newMemoryStore()
	handle := anchor.PersistentHandleFirst + 98
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		handle,
		handle+1,
	)
	manager, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA); err == nil {
		t.Fatal("EnsureRole ignored injected response loss")
	}
	if !backend.hasHandle(handle) {
		t.Fatal("fake did not model successful persistence before response loss")
	}
	if _, exists := store.snapshot.Pending[RoleDeviceRootCA]; !exists {
		t.Fatal("response loss left no recoverable creation intent")
	}

	reopened, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered := store.snapshot.Roles[RoleDeviceRootCA]
	if recovered.Active.Handle != handle || recovered.Active.Generation != 1 {
		t.Fatalf("recovered role = %#v, want first generation", recovered)
	}
}

func TestPendingCreationNeverAdoptsMismatchedOccupiedHandle(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	handle := anchor.PersistentHandleFirst + 102
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		handle,
		handle+1,
	)
	manager, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	backend.createResponseLosses = 1
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA); err == nil {
		t.Fatal("EnsureRole ignored injected response loss")
	}
	pending := store.snapshot.Pending[RoleDeviceRootCA]
	backend.replaceName(handle, []byte("unrelated-object-name"))

	reopened, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Open(context.Background()); !errors.Is(err, ErrMetadataMismatch) {
		t.Fatalf("Open error = %v, want metadata mismatch", err)
	}
	if _, exists := store.snapshot.Roles[RoleDeviceRootCA]; exists {
		t.Fatal("mismatched occupied handle was adopted")
	}
	if stored := store.snapshot.Pending[RoleDeviceRootCA]; !reflect.DeepEqual(stored, pending) {
		t.Fatal("mismatched pending metadata was silently rewritten")
	}
}

func TestIncompleteRetirementIsRecoveredOnReopen(t *testing.T) {
	start := time.Now().UTC()
	clock := &fakeClock{now: start}
	backend := newFakeBackend()
	store := newMemoryStore()
	firstHandle := anchor.PersistentHandleFirst + 100
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		firstHandle,
		firstHandle+1,
		firstHandle+2,
	)
	manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA); err != nil {
		t.Fatal(err)
	}
	backend.evictFailures = 1
	clock.Set(start.Add(24 * time.Hour))
	rotated, err := manager.Rotate(context.Background(), RoleDeviceRootCA)
	if err == nil {
		t.Fatal("Rotate did not report injected retirement failure")
	}
	if rotated.Generation != 2 || rotated.Handle != firstHandle+1 {
		t.Fatalf("activated metadata = %#v, want generation two", rotated)
	}
	pending := store.snapshot.Roles[RoleDeviceRootCA]
	if pending.Active.Generation != 2 || len(pending.Retiring) != 1 {
		t.Fatalf("pending rotation state = %#v", pending)
	}

	reopened, err := NewManager(backend, store, []RolePolicy{policy}, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered := store.snapshot.Roles[RoleDeviceRootCA]
	if recovered.Active.Generation != 2 || len(recovered.Retiring) != 0 {
		t.Fatalf("recovered rotation state = %#v", recovered)
	}
	if backend.hasHandle(firstHandle) {
		t.Fatal("reopen did not evict verified superseded handle")
	}
}

func TestEnsureRoleRejectsRevisionOverflowBeforeTPMMutation(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	store.snapshot.Revision = math.MaxUint64 - 1
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		anchor.PersistentHandleFirst+110,
		anchor.PersistentHandleFirst+111,
	)
	manager, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(
		context.Background(),
		RoleDeviceRootCA,
	); !errors.Is(err, ErrMetadataCounterExhausted) {
		t.Fatalf("EnsureRole error = %v, want counter exhaustion", err)
	}
	if backend.createCalls != 0 {
		t.Fatalf("TPM create calls = %d, want zero", backend.createCalls)
	}
}

func TestRotateRejectsGenerationOverflowBeforeTPMMutation(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	policy := caPolicy(
		RoleDeviceRootCA,
		anchor.AlgorithmECDSAP256,
		anchor.PersistentHandleFirst+112,
		anchor.PersistentHandleFirst+113,
	)
	manager, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA); err != nil {
		t.Fatal(err)
	}
	store.mutate(func(snapshot *Snapshot) {
		state := snapshot.Roles[RoleDeviceRootCA]
		state.Active.Generation = math.MaxUint64
		snapshot.Roles[RoleDeviceRootCA] = state
	})
	reopened, err := NewManager(
		backend,
		store,
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Rotate(
		context.Background(),
		RoleDeviceRootCA,
	); !errors.Is(err, ErrMetadataCounterExhausted) {
		t.Fatalf("Rotate error = %v, want counter exhaustion", err)
	}
	if backend.createCalls != 1 {
		t.Fatalf("TPM create calls = %d, want initial create only", backend.createCalls)
	}
}

func TestManagersSerializePendingPersistenceAndRefreshEveryRead(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	roleA := Role("concurrent-ca-a")
	roleB := Role("concurrent-ca-b")
	handleA := anchor.PersistentHandleFirst + 300
	handleB := anchor.PersistentHandleFirst + 302
	policies := []RolePolicy{
		caPolicy(
			roleA,
			anchor.AlgorithmECDSAP256,
			handleA,
			handleA+1,
		),
		caPolicy(
			roleB,
			anchor.AlgorithmECDSAP256,
			handleB,
			handleB+1,
		),
	}
	clock := &fakeClock{now: time.Now().UTC()}
	first, err := NewManager(backend, store, policies, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewManager(backend, store, policies, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot, err := second.PublicSnapshot(
		context.Background(),
	); err != nil || snapshot.Revision != 0 {
		t.Fatalf("initial second-manager snapshot = %#v, error = %v", snapshot, err)
	}

	prepared := make(chan struct{})
	continuePersistence := make(chan struct{})
	var pauseOnce sync.Once
	backend.afterPrepare = func() {
		pauseOnce.Do(func() {
			close(prepared)
			<-continuePersistence
		})
	}
	type metadataResult struct {
		metadata KeyMetadata
		err      error
	}
	createResult := make(chan metadataResult, 1)
	go func() {
		metadata, createErr := first.EnsureRole(context.Background(), roleA)
		createResult <- metadataResult{metadata: metadata, err: createErr}
	}()
	select {
	case <-prepared:
	case <-time.After(5 * time.Second):
		t.Fatal("first manager did not reach prepared creation intent")
	}

	openResult := make(chan error, 1)
	go func() {
		openResult <- second.Open(context.Background())
	}()
	metadataRead := make(chan metadataResult, 1)
	go func() {
		metadata, readErr := second.Metadata(context.Background(), roleA)
		metadataRead <- metadataResult{metadata: metadata, err: readErr}
	}()
	type snapshotResult struct {
		snapshot Snapshot
		err      error
	}
	snapshotRead := make(chan snapshotResult, 1)
	go func() {
		snapshot, readErr := second.PublicSnapshot(context.Background())
		snapshotRead <- snapshotResult{snapshot: snapshot, err: readErr}
	}()

	select {
	case err := <-openResult:
		t.Fatalf("Open escaped an in-flight persistence transaction: %v", err)
	case result := <-metadataRead:
		t.Fatalf(
			"Metadata escaped an in-flight persistence transaction: %#v",
			result,
		)
	case result := <-snapshotRead:
		t.Fatalf(
			"PublicSnapshot escaped an in-flight persistence transaction: %#v",
			result,
		)
	case <-time.After(100 * time.Millisecond):
	}
	close(continuePersistence)
	select {
	case result := <-createResult:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.metadata.Handle != handleA {
			t.Fatalf("created handle = %#x, want %#x", result.metadata.Handle, handleA)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first manager did not finish creation")
	}
	select {
	case err := <-openResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second manager Open remained blocked")
	}
	select {
	case result := <-metadataRead:
		if result.err != nil || result.metadata.Handle != handleA {
			t.Fatalf("fresh Metadata = %#v, error = %v", result.metadata, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second manager Metadata remained blocked")
	}
	select {
	case result := <-snapshotRead:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.snapshot.Roles[roleA].Active.Handle != handleA {
			t.Fatalf("fresh PublicSnapshot = %#v", result.snapshot)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second manager PublicSnapshot remained blocked")
	}

	metadataB, err := second.EnsureRole(context.Background(), roleB)
	if err != nil {
		t.Fatal(err)
	}
	if metadataB.Handle != handleB {
		t.Fatalf("second role handle = %#x, want %#x", metadataB.Handle, handleB)
	}
	finalSnapshot, err := first.PublicSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if finalSnapshot.Roles[roleA].Active.Handle != handleA ||
		finalSnapshot.Roles[roleB].Active.Handle != handleB ||
		len(finalSnapshot.Pending) != 0 {
		t.Fatalf("serialized final snapshot = %#v", finalSnapshot)
	}
	if !backend.hasHandle(handleA) || !backend.hasHandle(handleB) {
		t.Fatal("serialized manager operations left a missing TPM object")
	}
}

func TestOpenRejectsEveryLifetimeIdentityReplacementState(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*Snapshot, KeyMetadata)
	}{
		{
			name: "advanced active generation",
			mutate: func(snapshot *Snapshot, metadata KeyMetadata) {
				state := snapshot.Roles[RoleDeviceIPNSIdentity]
				state.Active.Generation = 2
				snapshot.Roles[RoleDeviceIPNSIdentity] = state
			},
		},
		{
			name: "retiring identity",
			mutate: func(snapshot *Snapshot, metadata KeyMetadata) {
				state := snapshot.Roles[RoleDeviceIPNSIdentity]
				state.Retiring = []KeyMetadata{cloneKeyMetadata(metadata)}
				snapshot.Roles[RoleDeviceIPNSIdentity] = state
			},
		},
		{
			name: "replacement pending identity",
			mutate: func(snapshot *Snapshot, metadata KeyMetadata) {
				replacement := cloneKeyMetadata(metadata)
				replacement.Generation = 2
				snapshot.Pending[RoleDeviceIPNSIdentity] = replacement
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := newFakeBackend()
			store := newMemoryStore()
			handle := anchor.PersistentHandleFirst + 320
			policy := identityPolicy(anchor.AlgorithmEd25519, handle)
			manager, err := NewManager(
				backend,
				store,
				[]RolePolicy{policy},
				nil,
				&fakeClock{now: time.Now().UTC()},
			)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := manager.EnsureRole(
				context.Background(),
				RoleDeviceIPNSIdentity,
			)
			if err != nil {
				t.Fatal(err)
			}
			store.mutate(func(snapshot *Snapshot) {
				testCase.mutate(snapshot, metadata)
			})
			reopened, err := NewManager(
				backend,
				store,
				[]RolePolicy{policy},
				nil,
				&fakeClock{now: time.Now().UTC()},
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.Open(
				context.Background(),
			); !errors.Is(err, ErrMetadataMismatch) {
				t.Fatalf("Open error = %v, want metadata mismatch", err)
			}
			if backend.evictCalls != 0 {
				t.Fatalf("TPM eviction calls = %d, want zero", backend.evictCalls)
			}
			if !backend.hasHandle(handle) {
				t.Fatal("corrupted snapshot caused lifetime identity eviction")
			}
		})
	}
}

func TestManagerHasNoExportedRawSigningOrExportOracle(t *testing.T) {
	managerType := reflect.TypeOf((*Manager)(nil))
	want := []string{
		"EnsureRole",
		"Initialize",
		"IssueCertificate",
		"Metadata",
		"Open",
		"PublicSnapshot",
		"ReconcileRetiring",
		"Rotate",
	}
	got := make([]string, 0, managerType.NumMethod())
	for index := 0; index < managerType.NumMethod(); index++ {
		got = append(got, managerType.Method(index).Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Manager exported methods = %v, want exactly %v", got, want)
	}
}
