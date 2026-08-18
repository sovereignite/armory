// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

// Package keymanager manages non-exportable TPM signing keys by persistent
// handle and exposes only purpose-specific signing workflows.
package keymanager

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/sovereignite/anchor"
)

// MetadataVersion is the only public-metadata schema version understood by
// this implementation.
const MetadataVersion = 1

// Role separates TPM handles by their intended system responsibility.
type Role string

const (
	// RoleDeviceIPNSIdentity is the lifetime device and IPNS identity. It is
	// explicitly ineligible for ordinary rotation.
	RoleDeviceIPNSIdentity Role = "device-ipns-identity"

	// RoleDeviceRootCA is the lifetime device root certificate authority.
	// It signs all subordinate CAs and is explicitly ineligible for rotation.
	RoleDeviceRootCA Role = "device-root-ca"

	// RoleKubernetesAPICA is the Kubernetes API server certificate authority.
	RoleKubernetesAPICA Role = "k8s-api-ca"

	// RoleEtcdCA is the etcd certificate authority.
	RoleEtcdCA Role = "etcd-ca"

	// RoleServiceAccountSigning is the Kubernetes service account signing key.
	RoleServiceAccountSigning Role = "sa-signing"

	// RoleFrontProxyCA is the Kubernetes API aggregation front proxy CA.
	RoleFrontProxyCA Role = "front-proxy-ca"

	// RoleSPIREServerCA is the SPIRE server certificate authority.
	RoleSPIREServerCA Role = "spire-server-ca"

	// RoleIstioCA is the Istio service mesh certificate authority.
	RoleIstioCA Role = "istio-ca"

	// RoleDeviceMTLS is the device mTLS leaf certificate key.
	RoleDeviceMTLS Role = "device-mtls"

	// RoleFederationCrossCert is the federation cross-certificate key.
	RoleFederationCrossCert Role = "federation-cross"

	// RoleMobileClient is the mobile client enrollment certificate key.
	RoleMobileClient Role = "mobile-client"
)

// KeyPurpose controls which high-level operation may use a role.
type KeyPurpose string

const (
	PurposeDeviceIPNSIdentity   KeyPurpose = "device-ipns-identity"
	PurposeCertificateAuthority KeyPurpose = "certificate-authority"
	PurposeSigning              KeyPurpose = "signing"
)

// RolePolicy is immutable key-manager configuration for one separated role.
//
// Handles is an ordered, role-exclusive pool. The first unused handle is used
// at initial creation and subsequent entries are used by rotation.
type RolePolicy struct {
	Role             Role
	Purpose          KeyPurpose
	Algorithm        tpm.Algorithm
	Handles          []tpm.Handle
	Lifetime         bool
	RotationInterval time.Duration
}

// KeyMetadata contains only public TPM and scheduling information.
type KeyMetadata struct {
	Role         Role          `json:"role"`
	Purpose      KeyPurpose    `json:"purpose"`
	Algorithm    tpm.Algorithm `json:"algorithm"`
	Handle       tpm.Handle    `json:"persistent_handle"`
	PublicName   []byte        `json:"public_name"`
	PublicKeyDER []byte        `json:"public_key_spki"`
	Template     tpm.Template  `json:"template"`
	CreatedAt    time.Time     `json:"created_at"`
	Generation   uint64        `json:"generation"`
}

// RoleState records the active public identity and any superseded object whose
// verified handle still needs eviction after a crash or partial I/O failure.
type RoleState struct {
	Active   KeyMetadata   `json:"active"`
	Retiring []KeyMetadata `json:"retiring,omitempty"`
}

// Snapshot is the versioned, atomically persisted public metadata document.
type Snapshot struct {
	Version  int                  `json:"version"`
	Revision uint64               `json:"revision"`
	Roles    map[Role]RoleState   `json:"roles"`
	Pending  map[Role]KeyMetadata `json:"pending_creations,omitempty"`
}

// Store persists only Snapshot values. Implementations must never accept or
// synthesize private-key fields. If Save atomically replaces the visible
// snapshot but cannot confirm its durability, it must return an error wrapping
// ErrMetadataDurabilityUncertain. Save must reject any replacement whose
// revision is not exactly one greater than the currently visible snapshot with
// ErrMetadataRevisionConflict.
type Store interface {
	Load() (Snapshot, error)
	Save(Snapshot) error
}

// exclusiveStore is deliberately internal: Manager accepts only stores that
// can serialize one full metadata/TPM mutation across cooperating processes.
// The transaction view must not release its exclusion between Load and Save.
type exclusiveStore interface {
	withExclusive(context.Context, func(Store) error) error
}

var rolePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$`)

func validatePolicies(policies []RolePolicy) (map[Role]RolePolicy, []Role, error) {
	if len(policies) == 0 {
		return nil, nil, errors.New("at least one key role policy is required")
	}
	byRole := make(map[Role]RolePolicy, len(policies))
	handleRoles := make(map[tpm.Handle]Role)
	order := make([]Role, 0, len(policies))
	for _, input := range policies {
		policy := clonePolicy(input)
		if !rolePattern.MatchString(string(policy.Role)) {
			return nil, nil, fmt.Errorf("invalid key role %q", policy.Role)
		}
		if _, exists := byRole[policy.Role]; exists {
			return nil, nil, fmt.Errorf("duplicate key role %q", policy.Role)
		}
		if _, err := tpm.SigningTemplate(policy.Algorithm); err != nil {
			return nil, nil, fmt.Errorf("role %q algorithm: %w", policy.Role, err)
		}
		if len(policy.Handles) == 0 {
			return nil, nil, fmt.Errorf("role %q has no persistent handles", policy.Role)
		}
		localHandles := make(map[tpm.Handle]struct{}, len(policy.Handles))
		for _, handle := range policy.Handles {
			if !handle.IsPersistent() {
				return nil, nil, fmt.Errorf(
					"role %q handle %#x is outside the persistent range",
					policy.Role,
					uint32(handle),
				)
			}
			if _, exists := localHandles[handle]; exists {
				return nil, nil, fmt.Errorf(
					"role %q repeats handle %#x",
					policy.Role,
					uint32(handle),
				)
			}
			if owner, exists := handleRoles[handle]; exists {
				return nil, nil, fmt.Errorf(
					"persistent handle %#x is shared by roles %q and %q",
					uint32(handle),
					owner,
					policy.Role,
				)
			}
			localHandles[handle] = struct{}{}
			handleRoles[handle] = policy.Role
		}
		switch policy.Purpose {
		case PurposeDeviceIPNSIdentity:
			if policy.Role != RoleDeviceIPNSIdentity {
				return nil, nil, fmt.Errorf(
					"lifetime identity purpose must use role %q",
					RoleDeviceIPNSIdentity,
				)
			}
			if !policy.Lifetime || policy.RotationInterval != 0 {
				return nil, nil, fmt.Errorf(
					"role %q must be lifetime and have no rotation interval",
					policy.Role,
				)
			}
			if len(policy.Handles) != 1 {
				return nil, nil, fmt.Errorf(
					"lifetime role %q requires exactly one persistent handle",
					policy.Role,
				)
			}
		case PurposeCertificateAuthority:
			if policy.Role == RoleDeviceIPNSIdentity {
				return nil, nil, fmt.Errorf(
					"role %q cannot be a certificate-authority role",
					policy.Role,
				)
			}
			if policy.Lifetime {
				return nil, nil, fmt.Errorf(
					"certificate-authority role %q cannot be lifetime",
					policy.Role,
				)
			}
			if policy.RotationInterval <= 0 {
				return nil, nil, fmt.Errorf(
					"certificate-authority role %q requires a positive rotation interval",
					policy.Role,
				)
			}
			if len(policy.Handles) < 2 {
				return nil, nil, fmt.Errorf(
					"rotatable role %q requires at least two separated handles",
					policy.Role,
				)
			}
		case PurposeSigning:
			if policy.Role == RoleDeviceIPNSIdentity {
				return nil, nil, fmt.Errorf(
					"role %q cannot use signing purpose",
					policy.Role,
				)
			}
			if !policy.Lifetime || policy.RotationInterval != 0 {
				return nil, nil, fmt.Errorf(
					"signing role %q must be lifetime with no rotation",
					policy.Role,
				)
			}
			if len(policy.Handles) != 1 {
				return nil, nil, fmt.Errorf(
					"signing role %q requires exactly one persistent handle",
					policy.Role,
				)
			}
		default:
			return nil, nil, fmt.Errorf(
				"role %q has unsupported purpose %q",
				policy.Role,
				policy.Purpose,
			)
		}
		byRole[policy.Role] = policy
		order = append(order, policy.Role)
	}
	return byRole, order, nil
}

func clonePolicy(policy RolePolicy) RolePolicy {
	policy.Handles = slices.Clone(policy.Handles)
	return policy
}

func emptySnapshot() Snapshot {
	return Snapshot{
		Version: MetadataVersion,
		Roles:   make(map[Role]RoleState),
		Pending: make(map[Role]KeyMetadata),
	}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	cloned := Snapshot{
		Version:  snapshot.Version,
		Revision: snapshot.Revision,
		Roles:    make(map[Role]RoleState, len(snapshot.Roles)),
		Pending:  make(map[Role]KeyMetadata, len(snapshot.Pending)),
	}
	for role, state := range snapshot.Roles {
		state.Active = cloneKeyMetadata(state.Active)
		state.Retiring = slices.Clone(state.Retiring)
		for index := range state.Retiring {
			state.Retiring[index] = cloneKeyMetadata(state.Retiring[index])
		}
		cloned.Roles[role] = state
	}
	for role, metadata := range snapshot.Pending {
		cloned.Pending[role] = cloneKeyMetadata(metadata)
	}
	return cloned
}

func cloneKeyMetadata(metadata KeyMetadata) KeyMetadata {
	metadata.PublicName = slices.Clone(metadata.PublicName)
	metadata.PublicKeyDER = slices.Clone(metadata.PublicKeyDER)
	return metadata
}
