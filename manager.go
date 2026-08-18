// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/sovereignite/tpm"
)

// Clock makes creation and rotation decisions deterministic in tests.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time {
	return time.Now()
}

// Manager owns role policy, public metadata, and access to an injected TPM.
type Manager struct {
	mu sync.Mutex

	backend           tpm.Backend
	store             Store
	transactionStore  Store
	clock             Clock
	certificatePolicy CertificatePolicy
	policies          map[Role]RolePolicy
	order             []Role

	loaded   bool
	snapshot Snapshot
}

// NewManager validates that every configured persistent handle belongs to
// exactly one role.
func NewManager(
	backend tpm.Backend,
	store Store,
	policies []RolePolicy,
	certificatePolicy CertificatePolicy,
	clock Clock,
) (*Manager, error) {
	if backend == nil {
		return nil, errors.New("TPM backend is required")
	}
	if store == nil {
		return nil, errors.New("metadata store is required")
	}
	if _, ok := store.(exclusiveStore); !ok {
		return nil, errors.New(
			"metadata store must serialize complete key-manager mutations",
		)
	}
	if clock == nil {
		clock = wallClock{}
	}
	byRole, order, err := validatePolicies(policies)
	if err != nil {
		return nil, err
	}
	return &Manager{
		backend:           backend,
		store:             store,
		clock:             clock,
		certificatePolicy: certificatePolicy,
		policies:          byRole,
		order:             order,
	}, nil
}

// Open reloads metadata and verifies every stored handle, public name, key, and
// template against the live TPM. It never generates a replacement on failure.
func (m *Manager) Open(ctx context.Context) error {
	return m.withExclusiveOperation(ctx, func() error {
		return m.openLocked(ctx)
	})
}

// EnsureRole returns an existing verified role or creates its first TPM object.
func (m *Manager) EnsureRole(ctx context.Context, role Role) (KeyMetadata, error) {
	var metadata KeyMetadata
	err := m.withExclusiveOperation(ctx, func() error {
		var operationErr error
		metadata, operationErr = m.ensureRoleLocked(ctx, role)
		return operationErr
	})
	return metadata, err
}

func (m *Manager) ensureRoleLocked(
	ctx context.Context,
	role Role,
) (KeyMetadata, error) {
	if err := m.ensureLoadedLocked(ctx); err != nil {
		return KeyMetadata{}, err
	}
	policy, exists := m.policies[role]
	if !exists {
		return KeyMetadata{}, fmt.Errorf("%w: %q", ErrRoleNotConfigured, role)
	}
	if state, exists := m.snapshot.Roles[role]; exists {
		if err := m.verifyMetadataLocked(ctx, state.Active); err != nil {
			return KeyMetadata{}, err
		}
		return cloneKeyMetadata(state.Active), nil
	}

	handle, err := m.initialHandleLocked(ctx, policy)
	if err != nil {
		return KeyMetadata{}, err
	}
	if err := m.requireRevisionCapacityLocked(2); err != nil {
		return KeyMetadata{}, err
	}
	metadata, err := m.createMetadataLocked(ctx, policy, handle, 1)
	if err != nil {
		return KeyMetadata{}, err
	}
	next := cloneSnapshot(m.snapshot)
	next.Roles[role] = RoleState{Active: metadata}
	delete(next.Pending, role)
	if err := incrementRevision(&next); err != nil {
		return cloneKeyMetadata(metadata), err
	}
	committed, err := m.persistSnapshotLocked(next)
	if err != nil {
		return cloneKeyMetadata(metadata), fmt.Errorf(
			"activate newly created role %q (committed=%t): %w",
			role,
			committed,
			err,
		)
	}
	return cloneKeyMetadata(metadata), nil
}

// Metadata returns the verified active public metadata for one role.
func (m *Manager) Metadata(ctx context.Context, role Role) (KeyMetadata, error) {
	var metadata KeyMetadata
	err := m.withExclusiveOperation(ctx, func() error {
		if err := m.ensureLoadedLocked(ctx); err != nil {
			return err
		}
		state, exists := m.snapshot.Roles[role]
		if !exists {
			if _, configured := m.policies[role]; !configured {
				return fmt.Errorf("%w: %q", ErrRoleNotConfigured, role)
			}
			return fmt.Errorf("key role %q has not been initialized", role)
		}
		if err := m.verifyMetadataLocked(ctx, state.Active); err != nil {
			return err
		}
		metadata = cloneKeyMetadata(state.Active)
		return nil
	})
	return metadata, err
}

// PublicSnapshot returns a deep copy of the public-only persistence model.
func (m *Manager) PublicSnapshot(ctx context.Context) (Snapshot, error) {
	var snapshot Snapshot
	err := m.withExclusiveOperation(ctx, func() error {
		if err := m.ensureLoadedLocked(ctx); err != nil {
			return err
		}
		snapshot = cloneSnapshot(m.snapshot)
		return nil
	})
	return snapshot, err
}

// Rotate activates a newly generated persistent TPM key for a subordinate role
// and then retires the old handle. The lifetime device/IPNS identity is always
// rejected.
func (m *Manager) Rotate(ctx context.Context, role Role) (KeyMetadata, error) {
	var metadata KeyMetadata
	err := m.withExclusiveOperation(ctx, func() error {
		var operationErr error
		metadata, operationErr = m.rotateLocked(ctx, role)
		return operationErr
	})
	return metadata, err
}

func (m *Manager) rotateLocked(ctx context.Context, role Role) (KeyMetadata, error) {
	if err := m.ensureLoadedLocked(ctx); err != nil {
		return KeyMetadata{}, err
	}
	policy, exists := m.policies[role]
	if !exists {
		return KeyMetadata{}, fmt.Errorf("%w: %q", ErrRoleNotConfigured, role)
	}
	if role == RoleDeviceIPNSIdentity || policy.Purpose == PurposeDeviceIPNSIdentity ||
		policy.Lifetime {
		return KeyMetadata{}, ErrLifetimeIdentityRotation
	}
	state, exists := m.snapshot.Roles[role]
	if !exists {
		return KeyMetadata{}, fmt.Errorf("key role %q has not been initialized", role)
	}
	if err := m.verifyMetadataLocked(ctx, state.Active); err != nil {
		return KeyMetadata{}, err
	}
	if state.Active.Generation == math.MaxUint64 {
		return KeyMetadata{}, fmt.Errorf(
			"%w: role %q generation",
			ErrMetadataCounterExhausted,
			role,
		)
	}
	if err := m.requireRevisionCapacityLocked(3); err != nil {
		return KeyMetadata{}, err
	}
	handle, err := m.rotationHandleLocked(ctx, policy, state)
	if err != nil {
		return KeyMetadata{}, err
	}
	metadata, err := m.createMetadataLocked(
		ctx,
		policy,
		handle,
		state.Active.Generation+1,
	)
	if err != nil {
		return KeyMetadata{}, err
	}

	next := cloneSnapshot(m.snapshot)
	nextState := next.Roles[role]
	nextState.Retiring = append(nextState.Retiring, nextState.Active)
	nextState.Active = metadata
	next.Roles[role] = nextState
	delete(next.Pending, role)
	if err := incrementRevision(&next); err != nil {
		return cloneKeyMetadata(metadata), err
	}
	committed, err := m.persistSnapshotLocked(next)
	if err != nil {
		return cloneKeyMetadata(metadata), fmt.Errorf(
			"activate rotated role %q at handle %#x (committed=%t): %w",
			role,
			uint32(metadata.Handle),
			committed,
			err,
		)
	}

	if err := m.reconcileRetiringLocked(ctx); err != nil {
		return cloneKeyMetadata(metadata), fmt.Errorf(
			"role %q activated at handle %#x but retirement is incomplete: %w",
			role,
			uint32(metadata.Handle),
			err,
		)
	}
	return cloneKeyMetadata(metadata), nil
}

func (m *Manager) rotateIfDue(
	ctx context.Context,
	role Role,
	now time.Time,
) (KeyMetadata, bool, error) {
	var metadata KeyMetadata
	rotated := false
	err := m.withExclusiveOperation(ctx, func() error {
		if err := m.ensureLoadedLocked(ctx); err != nil {
			return err
		}
		policy, exists := m.policies[role]
		if !exists {
			return fmt.Errorf("%w: %q", ErrRoleNotConfigured, role)
		}
		if role == RoleDeviceIPNSIdentity ||
			policy.Purpose == PurposeDeviceIPNSIdentity ||
			policy.Lifetime {
			return ErrLifetimeIdentityRotation
		}
		state, exists := m.snapshot.Roles[role]
		if !exists {
			return nil
		}
		if now.Before(state.Active.CreatedAt.Add(policy.RotationInterval)) {
			return nil
		}
		var rotateErr error
		metadata, rotateErr = m.rotateLocked(ctx, role)
		if rotateErr != nil {
			return rotateErr
		}
		rotated = true
		return nil
	})
	return metadata, rotated, err
}

// ReconcileRetiring verifies and evicts superseded handles left by a partial
// rotation, then atomically removes their public metadata.
func (m *Manager) ReconcileRetiring(ctx context.Context) error {
	return m.withExclusiveOperation(ctx, func() error {
		if err := m.ensureLoadedLocked(ctx); err != nil {
			return err
		}
		return m.reconcileRetiringLocked(ctx)
	})
}

func (m *Manager) openLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := m.operationStoreLocked().Load()
	if err != nil {
		return fmt.Errorf("load key metadata: %w", err)
	}
	if err := m.validateSnapshotLocked(snapshot); err != nil {
		return err
	}
	for _, role := range m.order {
		state, exists := snapshot.Roles[role]
		if !exists {
			continue
		}
		if err := m.verifyMetadataValue(ctx, state.Active); err != nil {
			return err
		}
		for _, metadata := range state.Retiring {
			public, readErr := m.backend.ReadPublic(ctx, metadata.Handle)
			if errors.Is(readErr, tpm.ErrHandleNotFound) {
				continue
			}
			if readErr != nil {
				return fmt.Errorf(
					"read retiring TPM handle %#x for role %q: %w",
					uint32(metadata.Handle),
					role,
					readErr,
				)
			}
			if err := verifyPublicMetadata(metadata, public); err != nil {
				return err
			}
		}
	}
	m.snapshot = snapshot
	m.loaded = true
	if err := m.reconcilePendingLocked(ctx); err != nil {
		m.loaded = false
		m.snapshot = Snapshot{}
		return err
	}
	if err := m.reconcileRetiringLocked(ctx); err != nil {
		m.loaded = false
		m.snapshot = Snapshot{}
		return err
	}
	return nil
}

func (m *Manager) ensureLoadedLocked(ctx context.Context) error {
	if !m.loaded {
		return m.openLocked(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.reconcilePendingLocked(ctx); err != nil {
		return err
	}
	return m.reconcileRetiringLocked(ctx)
}

func (m *Manager) validateSnapshotLocked(snapshot Snapshot) error {
	if err := validateSnapshotEnvelope(snapshot); err != nil {
		return err
	}
	seenHandles := make(map[tpm.Handle]Role)
	for role, state := range snapshot.Roles {
		policy, exists := m.policies[role]
		if !exists {
			return fmt.Errorf("%w in metadata: %q", ErrRoleNotConfigured, role)
		}
		if policy.Lifetime ||
			policy.Purpose == PurposeDeviceIPNSIdentity ||
			role == RoleDeviceIPNSIdentity {
			if state.Active.Generation != 1 || len(state.Retiring) != 0 {
				return fmt.Errorf(
					"%w: lifetime role %q has rotated state",
					ErrMetadataMismatch,
					role,
				)
			}
		}
		metadataValues := append(
			[]KeyMetadata{state.Active},
			state.Retiring...,
		)
		for index, metadata := range metadataValues {
			if err := validateMetadataForPolicy(role, policy, metadata); err != nil {
				return err
			}
			if index > 0 && metadata.Generation >= state.Active.Generation {
				return fmt.Errorf(
					"%w: retiring generation %d is not older than active generation %d for role %q",
					ErrMetadataMismatch,
					metadata.Generation,
					state.Active.Generation,
					role,
				)
			}
			if owner, exists := seenHandles[metadata.Handle]; exists {
				return fmt.Errorf(
					"%w: handle %#x is recorded for both %q and %q",
					ErrMetadataMismatch,
					uint32(metadata.Handle),
					owner,
					role,
				)
			}
			seenHandles[metadata.Handle] = role
		}
	}
	for role, metadata := range snapshot.Pending {
		policy, exists := m.policies[role]
		if !exists {
			return fmt.Errorf(
				"%w in pending metadata: %q",
				ErrRoleNotConfigured,
				role,
			)
		}
		if err := validateMetadataForPolicy(role, policy, metadata); err != nil {
			return err
		}
		if policy.Lifetime ||
			policy.Purpose == PurposeDeviceIPNSIdentity ||
			role == RoleDeviceIPNSIdentity {
			if _, hasActive := snapshot.Roles[role]; hasActive ||
				metadata.Generation != 1 {
				return fmt.Errorf(
					"%w: lifetime role %q has a replacement creation intent",
					ErrMetadataMismatch,
					role,
				)
			}
		}
		expectedGeneration := uint64(1)
		if state, exists := snapshot.Roles[role]; exists {
			if state.Active.Generation == math.MaxUint64 {
				return fmt.Errorf(
					"%w: active generation is exhausted for pending role %q",
					ErrMetadataCounterExhausted,
					role,
				)
			}
			expectedGeneration = state.Active.Generation + 1
		}
		if metadata.Generation != expectedGeneration {
			return fmt.Errorf(
				"%w: pending generation %d for role %q, expected %d",
				ErrMetadataMismatch,
				metadata.Generation,
				role,
				expectedGeneration,
			)
		}
		if owner, exists := seenHandles[metadata.Handle]; exists {
			return fmt.Errorf(
				"%w: pending handle %#x for role %q is already recorded for %q",
				ErrMetadataMismatch,
				uint32(metadata.Handle),
				role,
				owner,
			)
		}
		seenHandles[metadata.Handle] = role
	}
	return nil
}

func validateMetadataForPolicy(
	mapRole Role,
	policy RolePolicy,
	metadata KeyMetadata,
) error {
	if metadata.Role != mapRole || metadata.Role != policy.Role {
		return fmt.Errorf(
			"%w: metadata role %q does not match map role %q",
			ErrMetadataMismatch,
			metadata.Role,
			mapRole,
		)
	}
	if metadata.Purpose != policy.Purpose || metadata.Algorithm != policy.Algorithm {
		return fmt.Errorf(
			"%w: role %q purpose or algorithm changed",
			ErrMetadataMismatch,
			mapRole,
		)
	}
	if !slices.Contains(policy.Handles, metadata.Handle) {
		return fmt.Errorf(
			"%w: handle %#x is not assigned to role %q",
			ErrMetadataMismatch,
			uint32(metadata.Handle),
			mapRole,
		)
	}
	expectedTemplate, err := tpm.SigningTemplate(policy.Algorithm)
	if err != nil {
		return fmt.Errorf("%w: role %q template: %v", ErrMetadataMismatch, mapRole, err)
	}
	if metadata.Template != expectedTemplate {
		return fmt.Errorf("%w: role %q stored template changed", ErrMetadataMismatch, mapRole)
	}
	if metadata.Generation == 0 || metadata.CreatedAt.IsZero() ||
		len(metadata.PublicName) == 0 || len(metadata.PublicKeyDER) == 0 {
		return fmt.Errorf(
			"%w: role %q public metadata is incomplete",
			ErrMetadataMismatch,
			mapRole,
		)
	}
	return nil
}

func (m *Manager) verifyMetadataLocked(ctx context.Context, metadata KeyMetadata) error {
	return m.verifyMetadataValue(ctx, metadata)
}

func (m *Manager) verifyMetadataValue(ctx context.Context, metadata KeyMetadata) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	public, err := m.backend.ReadPublic(ctx, metadata.Handle)
	if err != nil {
		return fmt.Errorf(
			"%w: read handle %#x for role %q: %w",
			ErrMetadataMismatch,
			uint32(metadata.Handle),
			metadata.Role,
			err,
		)
	}
	return verifyPublicMetadata(metadata, public)
}

func verifyPublicMetadata(metadata KeyMetadata, public tpm.Public) error {
	if public.Handle != metadata.Handle {
		return fmt.Errorf(
			"%w: role %q returned handle %#x, expected %#x",
			ErrMetadataMismatch,
			metadata.Role,
			uint32(public.Handle),
			uint32(metadata.Handle),
		)
	}
	if public.Template != metadata.Template {
		return fmt.Errorf(
			"%w: role %q TPM template changed",
			ErrMetadataMismatch,
			metadata.Role,
		)
	}
	if subtle.ConstantTimeCompare(public.Name, metadata.PublicName) != 1 {
		return fmt.Errorf(
			"%w: role %q TPM public name changed",
			ErrMetadataMismatch,
			metadata.Role,
		)
	}
	publicDER, err := tpm.CanonicalPublicKey(public)
	if err != nil {
		return fmt.Errorf(
			"%w: role %q invalid TPM public key: %v",
			ErrMetadataMismatch,
			metadata.Role,
			err,
		)
	}
	if !bytes.Equal(publicDER, metadata.PublicKeyDER) {
		return fmt.Errorf(
			"%w: role %q TPM public key changed",
			ErrMetadataMismatch,
			metadata.Role,
		)
	}
	return nil
}

func (m *Manager) initialHandleLocked(
	ctx context.Context,
	policy RolePolicy,
) (tpm.Handle, error) {
	handle := policy.Handles[0]
	_, err := m.backend.ReadPublic(ctx, handle)
	if err == nil {
		return 0, fmt.Errorf(
			"%w: initial handle %#x for role %q",
			tpm.ErrHandleOccupied,
			uint32(handle),
			policy.Role,
		)
	}
	if !errors.Is(err, tpm.ErrHandleNotFound) {
		return 0, fmt.Errorf(
			"inspect initial handle %#x for role %q: %w",
			uint32(handle),
			policy.Role,
			err,
		)
	}
	return handle, nil
}

func (m *Manager) rotationHandleLocked(
	ctx context.Context,
	policy RolePolicy,
	state RoleState,
) (tpm.Handle, error) {
	recorded := make(map[tpm.Handle]struct{}, len(state.Retiring)+1)
	recorded[state.Active.Handle] = struct{}{}
	for _, metadata := range state.Retiring {
		recorded[metadata.Handle] = struct{}{}
	}
	occupied := false
	for _, handle := range policy.Handles {
		if _, exists := recorded[handle]; exists {
			continue
		}
		_, err := m.backend.ReadPublic(ctx, handle)
		switch {
		case errors.Is(err, tpm.ErrHandleNotFound):
			return handle, nil
		case err == nil:
			occupied = true
		default:
			return 0, fmt.Errorf(
				"inspect rotation handle %#x for role %q: %w",
				uint32(handle),
				policy.Role,
				err,
			)
		}
	}
	if occupied {
		return 0, errors.Join(
			fmt.Errorf("%w: %q", ErrNoHandleAvailable, policy.Role),
			tpm.ErrHandleOccupied,
		)
	}
	return 0, fmt.Errorf("%w: %q", ErrNoHandleAvailable, policy.Role)
}

func (m *Manager) createMetadataLocked(
	ctx context.Context,
	policy RolePolicy,
	handle tpm.Handle,
	generation uint64,
) (KeyMetadata, error) {
	if err := ctx.Err(); err != nil {
		return KeyMetadata{}, err
	}
	if err := m.backend.Supports(ctx, policy.Algorithm); err != nil {
		return KeyMetadata{}, fmt.Errorf(
			"TPM capability check for role %q: %w",
			policy.Role,
			err,
		)
	}
	template, err := tpm.SigningTemplate(policy.Algorithm)
	if err != nil {
		return KeyMetadata{}, err
	}
	createdAt := m.clock.Now().UTC()
	if createdAt.IsZero() {
		return KeyMetadata{}, errors.New("clock returned a zero creation time")
	}
	var metadata KeyMetadata
	prepared := false
	public, err := m.backend.CreatePersistent(
		ctx,
		handle,
		template,
		func(candidate tpm.Public) error {
			if prepared {
				return errors.New("TPM backend invoked persistent preparation more than once")
			}
			if candidate.Handle != handle || candidate.Template != template {
				return fmt.Errorf(
					"%w: TPM preparation for role %q returned unexpected handle or template",
					ErrMetadataMismatch,
					policy.Role,
				)
			}
			publicDER, publicErr := tpm.CanonicalPublicKey(candidate)
			if publicErr != nil {
				return fmt.Errorf(
					"validate prepared TPM public key for role %q: %w",
					policy.Role,
					publicErr,
				)
			}
			metadata = KeyMetadata{
				Role:         policy.Role,
				Purpose:      policy.Purpose,
				Algorithm:    policy.Algorithm,
				Handle:       handle,
				PublicName:   slices.Clone(candidate.Name),
				PublicKeyDER: publicDER,
				Template:     template,
				CreatedAt:    createdAt,
				Generation:   generation,
			}
			next := cloneSnapshot(m.snapshot)
			if _, exists := next.Pending[policy.Role]; exists {
				return fmt.Errorf(
					"%w: role %q already has a pending creation",
					ErrMetadataMismatch,
					policy.Role,
				)
			}
			next.Pending[policy.Role] = metadata
			if err := incrementRevision(&next); err != nil {
				return err
			}
			committed, saveErr := m.persistSnapshotLocked(next)
			if saveErr != nil {
				return fmt.Errorf(
					"record creation intent for role %q (committed=%t): %w",
					policy.Role,
					committed,
					saveErr,
				)
			}
			prepared = true
			return nil
		},
	)
	if err != nil {
		return KeyMetadata{}, fmt.Errorf(
			"create persistent TPM key for role %q: %w",
			policy.Role,
			err,
		)
	}
	if !prepared {
		cleanupErr := m.evictCreatedPublicLocked(ctx, handle, template, public)
		return KeyMetadata{}, errors.Join(
			errors.New("TPM backend persisted an object without preparation"),
			cleanupErr,
		)
	}
	if err := verifyPublicMetadata(metadata, public); err != nil {
		cleanupErr := m.evictCreatedPublicLocked(ctx, handle, template, public)
		return KeyMetadata{}, errors.Join(err, cleanupErr)
	}
	persisted, err := m.backend.ReadPublic(ctx, handle)
	if err != nil {
		cleanupErr := m.evictCreatedPublicLocked(ctx, handle, template, public)
		return KeyMetadata{}, errors.Join(
			fmt.Errorf("re-read created TPM key for role %q: %w", policy.Role, err),
			cleanupErr,
		)
	}
	if err := verifyPublicMetadata(metadata, persisted); err != nil {
		cleanupErr := m.evictCreatedPublicLocked(ctx, handle, template, public)
		return KeyMetadata{}, errors.Join(err, cleanupErr)
	}
	return metadata, nil
}

func (m *Manager) evictCreatedPublicLocked(
	ctx context.Context,
	expectedHandle tpm.Handle,
	expectedTemplate tpm.Template,
	public tpm.Public,
) error {
	if public.Handle != expectedHandle ||
		public.Template != expectedTemplate ||
		len(public.Name) == 0 {
		return errors.New("created TPM object could not be safely identified for rollback")
	}
	cleanupCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		10*time.Second,
	)
	defer cancel()
	if err := m.backend.EvictPersistent(cleanupCtx, tpm.ObjectReference{
		Handle:   public.Handle,
		Name:     slices.Clone(public.Name),
		Template: public.Template,
	}); err != nil && !errors.Is(err, tpm.ErrHandleNotFound) {
		return fmt.Errorf(
			"evict invalid created handle %#x: %w",
			uint32(public.Handle),
			err,
		)
	}
	return nil
}

func (m *Manager) reconcilePendingLocked(ctx context.Context) error {
	if !m.loaded || len(m.snapshot.Pending) == 0 {
		return nil
	}
	if err := m.requireRevisionCapacityLocked(1); err != nil {
		return err
	}
	next := cloneSnapshot(m.snapshot)
	changed := false
	for _, role := range m.order {
		metadata, exists := next.Pending[role]
		if !exists {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		public, err := m.backend.ReadPublic(ctx, metadata.Handle)
		if errors.Is(err, tpm.ErrHandleNotFound) {
			delete(next.Pending, role)
			changed = true
			continue
		}
		if err != nil {
			return fmt.Errorf(
				"read pending handle %#x for role %q: %w",
				uint32(metadata.Handle),
				role,
				err,
			)
		}
		if err := verifyPublicMetadata(metadata, public); err != nil {
			return fmt.Errorf("refuse to adopt mismatched pending handle: %w", err)
		}
		state, hasActive := next.Roles[role]
		if hasActive {
			state.Retiring = append(state.Retiring, state.Active)
		}
		state.Active = metadata
		next.Roles[role] = state
		delete(next.Pending, role)
		changed = true
	}
	if !changed {
		return nil
	}
	if err := incrementRevision(&next); err != nil {
		return err
	}
	_, err := m.persistSnapshotLocked(next)
	if err != nil {
		return fmt.Errorf("persist pending-creation recovery: %w", err)
	}
	return nil
}

func (m *Manager) reconcileRetiringLocked(ctx context.Context) error {
	if !m.loaded {
		return nil
	}
	hasRetiring := false
	for _, state := range m.snapshot.Roles {
		if len(state.Retiring) != 0 {
			hasRetiring = true
			break
		}
	}
	if hasRetiring {
		if err := m.requireRevisionCapacityLocked(1); err != nil {
			return err
		}
	}
	next := cloneSnapshot(m.snapshot)
	changed := false
	for _, role := range m.order {
		state, exists := next.Roles[role]
		if !exists || len(state.Retiring) == 0 {
			continue
		}
		for _, metadata := range state.Retiring {
			if err := ctx.Err(); err != nil {
				return err
			}
			public, err := m.backend.ReadPublic(ctx, metadata.Handle)
			if errors.Is(err, tpm.ErrHandleNotFound) {
				changed = true
				continue
			}
			if err != nil {
				return fmt.Errorf(
					"read retiring handle %#x for role %q: %w",
					uint32(metadata.Handle),
					role,
					err,
				)
			}
			if err := verifyPublicMetadata(metadata, public); err != nil {
				return fmt.Errorf("refuse to evict mismatched retiring handle: %w", err)
			}
			if err := m.backend.EvictPersistent(ctx, objectReference(metadata)); err != nil {
				return fmt.Errorf(
					"evict retiring handle %#x for role %q: %w",
					uint32(metadata.Handle),
					role,
					err,
				)
			}
			changed = true
		}
		state.Retiring = nil
		next.Roles[role] = state
	}
	if !changed {
		return nil
	}
	if err := incrementRevision(&next); err != nil {
		return err
	}
	_, err := m.persistSnapshotLocked(next)
	if err != nil {
		return fmt.Errorf("persist retired-handle cleanup: %w", err)
	}
	return nil
}

// persistSnapshotLocked preserves the TPM object whenever a store reports that
// its atomic replacement is already visible but its final durability barrier
// failed. Rolling the object back in that state would leave public metadata
// pointing at a missing TPM handle.
func (m *Manager) persistSnapshotLocked(next Snapshot) (bool, error) {
	err := m.operationStoreLocked().Save(next)
	if err == nil {
		m.snapshot = next
		return true, nil
	}
	if errors.Is(err, ErrMetadataDurabilityUncertain) {
		m.snapshot = next
		return true, err
	}
	if errors.Is(err, ErrMetadataRevisionConflict) {
		m.loaded = false
		m.snapshot = Snapshot{}
	}
	return false, err
}

func (m *Manager) withExclusiveOperation(
	ctx context.Context,
	operation func() error,
) error {
	if operation == nil {
		return errors.New("key-manager operation is required")
	}
	store, ok := m.store.(exclusiveStore)
	if !ok {
		return errors.New(
			"metadata store cannot serialize complete key-manager mutations",
		)
	}
	return store.withExclusive(ctx, func(transaction Store) error {
		if transaction == nil {
			return errors.New("metadata transaction store is unavailable")
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.transactionStore != nil {
			return errors.New("nested key-manager transactions are not allowed")
		}
		m.transactionStore = transaction
		m.loaded = false
		m.snapshot = Snapshot{}
		defer func() {
			m.transactionStore = nil
		}()
		return operation()
	})
}

func (m *Manager) operationStoreLocked() Store {
	if m.transactionStore != nil {
		return m.transactionStore
	}
	return m.store
}

func (m *Manager) requireRevisionCapacityLocked(steps uint64) error {
	if steps > math.MaxUint64-m.snapshot.Revision {
		return fmt.Errorf(
			"%w: revision %d cannot advance by %d",
			ErrMetadataCounterExhausted,
			m.snapshot.Revision,
			steps,
		)
	}
	return nil
}

func incrementRevision(snapshot *Snapshot) error {
	if snapshot.Revision == math.MaxUint64 {
		return fmt.Errorf(
			"%w: revision %d",
			ErrMetadataCounterExhausted,
			snapshot.Revision,
		)
	}
	snapshot.Revision++
	return nil
}

func objectReference(metadata KeyMetadata) tpm.ObjectReference {
	return tpm.ObjectReference{
		Handle:   metadata.Handle,
		Name:     slices.Clone(metadata.PublicName),
		Template: metadata.Template,
	}
}
