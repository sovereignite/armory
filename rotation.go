// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package armory

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RotationResult records one subordinate role activated by the scheduler.
type RotationResult struct {
	Role       Role
	Generation uint64
	Handle     uint32
	Activated  time.Time
}

// RotationScheduler runs only the reviewed subordinate-role schedules.
type RotationScheduler struct {
	manager      *Manager
	clock        Clock
	pollInterval time.Duration
}

// NewRotationScheduler creates a scheduler. The poll interval controls only
// how often due state is checked; each role's policy controls its key lifetime.
func NewRotationScheduler(
	manager *Manager,
	pollInterval time.Duration,
	clock Clock,
) (*RotationScheduler, error) {
	if manager == nil {
		return nil, errors.New("key manager is required")
	}
	if pollInterval <= 0 {
		return nil, errors.New("rotation poll interval must be positive")
	}
	if clock == nil {
		clock = wallClock{}
	}
	return &RotationScheduler{
		manager:      manager,
		clock:        clock,
		pollInterval: pollInterval,
	}, nil
}

// RunOnce rotates every initialized subordinate role whose interval has
// elapsed. A clock rollback never causes early rotation.
func (s *RotationScheduler) RunOnce(ctx context.Context) ([]RotationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	roles, err := s.manager.dueRoles(ctx, now)
	if err != nil {
		return nil, err
	}
	results := make([]RotationResult, 0, len(roles))
	var rotationErrors []error
	for _, role := range roles {
		if err := ctx.Err(); err != nil {
			rotationErrors = append(rotationErrors, err)
			break
		}
		metadata, rotated, rotateErr := s.manager.rotateIfDue(ctx, role, now)
		if rotateErr != nil {
			rotationErrors = append(
				rotationErrors,
				fmt.Errorf("rotate due role %q: %w", role, rotateErr),
			)
			continue
		}
		if !rotated {
			continue
		}
		results = append(results, RotationResult{
			Role:       role,
			Generation: metadata.Generation,
			Handle:     uint32(metadata.Handle),
			Activated:  metadata.CreatedAt,
		})
	}
	return results, errors.Join(rotationErrors...)
}

// Run checks immediately and then at each poll interval until cancellation.
// A failed rotation is returned so the supervising service can fail closed and
// retry visibly.
func (s *RotationScheduler) Run(ctx context.Context) error {
	if _, err := s.RunOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := s.RunOnce(ctx); err != nil {
				return err
			}
		}
	}
}

func (m *Manager) dueRoles(ctx context.Context, now time.Time) ([]Role, error) {
	var roles []Role
	err := m.withExclusiveOperation(ctx, func() error {
		if err := m.ensureLoadedLocked(ctx); err != nil {
			return err
		}
		roles = make([]Role, 0, len(m.order))
		for _, role := range m.order {
			policy := m.policies[role]
			if role == RoleDeviceIPNSIdentity ||
				policy.Purpose == PurposeDeviceIPNSIdentity ||
				policy.Lifetime ||
				policy.RotationInterval <= 0 {
				continue
			}
			state, exists := m.snapshot.Roles[role]
			if !exists {
				continue
			}
			dueAt := state.Active.CreatedAt.Add(policy.RotationInterval)
			if !now.Before(dueAt) {
				roles = append(roles, role)
			}
		}
		return nil
	})
	return roles, err
}
