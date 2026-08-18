// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import (
	"time"

	"github.com/sovereignite/anchor"
)

const operationalRotationInterval = 90 * 24 * time.Hour

// DefaultPolicies returns the production key-manager role policies with exact
// TPM persistent handle assignments from D-004.
//
// Bounded interpretation: D-004 marks device-mtls, federation-cross, and
// mobile-client as "Operational" but these are leaf signing keys, not CAs.
// Certificate renewal is performed by the CA without TPM key rotation, so
// these roles use Lifetime with a single handle. The existing type system
// enforces that PurposeSigning requires Lifetime=true and exactly 1 handle.
func DefaultPolicies() []RolePolicy {
	return []RolePolicy{
		{
			Role:             RoleDeviceIPNSIdentity,
			Purpose:          PurposeDeviceIPNSIdentity,
			Algorithm:        tpm.AlgorithmEd25519,
			Handles:          []tpm.Handle{0x81010001},
			Lifetime:         true,
			RotationInterval: 0,
		},
		{
			Role:             RoleDeviceRootCA,
			Purpose:          PurposeSigning,
			Algorithm:        tpm.AlgorithmRSA4096,
			Handles:          []tpm.Handle{0x81010010},
			Lifetime:         true,
			RotationInterval: 0,
		},
		{
			Role:             RoleKubernetesAPICA,
			Purpose:          PurposeCertificateAuthority,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010020, 0x81010021},
			Lifetime:         false,
			RotationInterval: operationalRotationInterval,
		},
		{
			Role:             RoleEtcdCA,
			Purpose:          PurposeCertificateAuthority,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010030, 0x81010031},
			Lifetime:         false,
			RotationInterval: operationalRotationInterval,
		},
		{
			Role:             RoleServiceAccountSigning,
			Purpose:          PurposeCertificateAuthority,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010040, 0x81010041},
			Lifetime:         false,
			RotationInterval: operationalRotationInterval,
		},
		{
			Role:             RoleFrontProxyCA,
			Purpose:          PurposeCertificateAuthority,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010050, 0x81010051},
			Lifetime:         false,
			RotationInterval: operationalRotationInterval,
		},
		{
			Role:             RoleSPIREServerCA,
			Purpose:          PurposeCertificateAuthority,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010060, 0x81010061},
			Lifetime:         false,
			RotationInterval: operationalRotationInterval,
		},
		{
			Role:             RoleIstioCA,
			Purpose:          PurposeCertificateAuthority,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010070, 0x81010071},
			Lifetime:         false,
			RotationInterval: operationalRotationInterval,
		},
		{
			Role:             RoleDeviceMTLS,
			Purpose:          PurposeSigning,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010080},
			Lifetime:         true,
			RotationInterval: 0,
		},
		{
			Role:             RoleFederationCrossCert,
			Purpose:          PurposeSigning,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x81010090},
			Lifetime:         true,
			RotationInterval: 0,
		},
		{
			Role:             RoleMobileClient,
			Purpose:          PurposeSigning,
			Algorithm:        tpm.AlgorithmECDSAP256,
			Handles:          []tpm.Handle{0x810100A0},
			Lifetime:         true,
			RotationInterval: 0,
		},
	}
}
