// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import (
	"context"
	"fmt"
)

// Initialize idempotently creates or reopens every configured role in policy
// order. Successfully committed earlier roles remain safe if a later hardware
// capability fails, and a retry re-verifies them rather than replacing them.
func (m *Manager) Initialize(ctx context.Context) ([]KeyMetadata, error) {
	results := make([]KeyMetadata, 0, len(m.order))
	for _, role := range m.order {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		metadata, err := m.EnsureRole(ctx, role)
		if err != nil {
			return results, fmt.Errorf("initialize key role %q: %w", role, err)
		}
		results = append(results, metadata)
	}
	return results, nil
}
