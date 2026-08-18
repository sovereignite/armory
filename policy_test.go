// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import (
	"testing"

	"github.com/sovereignite/anchor"
)

func TestDefaultPoliciesCount(t *testing.T) {
	policies := DefaultPolicies()
	if len(policies) != 11 {
		t.Fatalf("DefaultPolicies() returned %d policies, want 11", len(policies))
	}
}

func TestDefaultPoliciesPersistentHandles(t *testing.T) {
	policies := DefaultPolicies()
	for _, policy := range policies {
		for _, handle := range policy.Handles {
			if !handle.IsPersistent() {
				t.Errorf(
					"role %q handle %#x is outside the persistent range",
					policy.Role,
					uint32(handle),
				)
			}
		}
	}
}

func TestDefaultPoliciesUniqueHandles(t *testing.T) {
	policies := DefaultPolicies()
	seen := make(map[tpm.Handle]Role)
	for _, policy := range policies {
		for _, handle := range policy.Handles {
			if owner, exists := seen[handle]; exists {
				t.Errorf(
					"handle %#x is shared by roles %q and %q",
					uint32(handle),
					owner,
					policy.Role,
				)
			}
			seen[handle] = policy.Role
		}
	}
}

func TestDefaultPoliciesLifetimeRotation(t *testing.T) {
	policies := DefaultPolicies()
	for _, policy := range policies {
		if policy.Lifetime && policy.RotationInterval != 0 {
			t.Errorf(
				"role %q is lifetime but has non-zero rotation interval %v",
				policy.Role,
				policy.RotationInterval,
			)
		}
	}
}

func TestDefaultPoliciesOperationalRotation(t *testing.T) {
	policies := DefaultPolicies()
	for _, policy := range policies {
		if !policy.Lifetime && policy.RotationInterval <= 0 {
			t.Errorf(
				"role %q is operational but has non-positive rotation interval %v",
				policy.Role,
				policy.RotationInterval,
			)
		}
	}
}
