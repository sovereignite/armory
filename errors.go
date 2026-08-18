// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import "errors"

var (
	// ErrRoleNotConfigured is returned instead of inventing an unreviewed role
	// or handle assignment.
	ErrRoleNotConfigured = errors.New("key role is not configured")

	// ErrMetadataMismatch means a live TPM public name, public key, handle, or
	// template differs from the atomically stored public metadata.
	ErrMetadataMismatch = errors.New("TPM public metadata mismatch")

	// ErrLifetimeIdentityRotation rejects ordinary rotation of the device/IPNS
	// identity.
	ErrLifetimeIdentityRotation = errors.New("lifetime device/IPNS identity cannot be rotated")

	// ErrNoHandleAvailable means a role's reviewed persistent-handle pool is
	// exhausted.
	ErrNoHandleAvailable = errors.New("no persistent handle is available for role")

	// ErrCertificatePurposeDenied prevents a non-CA role from reaching the
	// certificate signer.
	ErrCertificatePurposeDenied = errors.New("key role is not authorized for certificate signing")

	// ErrCertificatePolicyUnavailable prevents signing before the caller has
	// supplied the v5 certificate-profile authorization policy.
	ErrCertificatePolicyUnavailable = errors.New("certificate policy is unavailable")

	// ErrMetadataDurabilityUncertain means the atomic replacement became
	// visible, but the store could not confirm that the containing directory
	// reached durable storage. Callers must not roll back the TPM object
	// referenced by the visible snapshot.
	ErrMetadataDurabilityUncertain = errors.New("metadata replacement durability is uncertain")

	// ErrMetadataCounterExhausted rejects revision or generation wrap before
	// any TPM mutation.
	ErrMetadataCounterExhausted = errors.New("metadata revision or generation is exhausted")

	// ErrMetadataRevisionConflict rejects a stale whole-snapshot replacement.
	// The caller must reload and re-verify live TPM state before retrying.
	ErrMetadataRevisionConflict = errors.New("metadata revision conflict")
)
