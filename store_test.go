// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sovereignite/tpm"
)

func TestFileStoreAtomicallyPersistsVersionedPublicMetadata(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "metadata.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first := emptySnapshot()
	first.Revision = 1
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	second := emptySnapshot()
	second.Revision = 2
	if err := store.Save(second); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != MetadataVersion || loaded.Revision != 2 {
		t.Fatalf("loaded snapshot = %#v, want version one revision two", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("metadata permissions = %04o, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "metadata.json" {
		t.Fatalf("metadata directory entries = %v, want only metadata.json", entries)
	}
}

func TestFileStoreReturnsIndependentSnapshots(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metadata.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := emptySnapshot()
	snapshot.Revision = 1
	snapshot.Roles[RoleDeviceRootCA] = RoleState{
		Active: KeyMetadata{
			Role:         RoleDeviceRootCA,
			PublicName:   []byte("public-name"),
			PublicKeyDER: []byte("public-key"),
		},
	}
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	state := loaded.Roles[RoleDeviceRootCA]
	state.Active.PublicName[0] ^= 0xff
	loaded.Roles[RoleDeviceRootCA] = state

	reloaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(
		reloaded.Roles[RoleDeviceRootCA].Active.PublicName,
		[]byte("public-name"),
	) {
		t.Fatal("mutating a loaded snapshot changed persisted metadata")
	}
}

func TestFileStoreRejectsStaleWholeSnapshotReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metadata.json")
	firstStore, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	first.Revision++
	if err := firstStore.Save(first); err != nil {
		t.Fatal(err)
	}
	second.Revision++
	if err := secondStore.Save(second); !errors.Is(
		err,
		ErrMetadataRevisionConflict,
	) {
		t.Fatalf("stale Save error = %v, want revision conflict", err)
	}
	loaded, err := firstStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != first.Revision {
		t.Fatalf(
			"revision after stale Save = %d, want %d",
			loaded.Revision,
			first.Revision,
		)
	}
}

func TestMemoryStoreRejectsStaleWholeSnapshotReplacement(t *testing.T) {
	store := newMemoryStore()
	first := emptySnapshot()
	first.Revision = 1
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	stale := emptySnapshot()
	stale.Revision = 1
	if err := store.Save(stale); !errors.Is(
		err,
		ErrMetadataRevisionConflict,
	) {
		t.Fatalf("stale memory Save error = %v, want revision conflict", err)
	}
	if store.snapshot.Revision != 1 {
		t.Fatalf(
			"memory revision after stale Save = %d, want 1",
			store.snapshot.Revision,
		)
	}
}

func TestFileStoreExclusiveWaitHonorsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(filepath.Join(dir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{})
	release := make(chan struct{})
	holderResult := make(chan error, 1)
	go func() {
		holderResult <- store.withExclusive(
			context.Background(),
			func(Store) error {
				close(acquired)
				<-release
				return nil
			},
		)
	}()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("exclusive metadata transaction did not acquire")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.withExclusive(ctx, func(Store) error {
		t.Fatal("canceled exclusive operation was invoked")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transaction error = %v, want context canceled", err)
	}
	close(release)
	select {
	case err := <-holderResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exclusive metadata transaction did not release")
	}
}

func TestFileStoreRejectsUnknownVersionAndFields(t *testing.T) {
	testCases := []struct {
		name string
		data any
	}{
		{
			name: "unknown version",
			data: map[string]any{
				"version":  MetadataVersion + 1,
				"revision": 0,
				"roles":    map[string]any{},
			},
		},
		{
			name: "unknown field",
			data: map[string]any{
				"version":    MetadataVersion,
				"revision":   0,
				"roles":      map[string]any{},
				"privateKey": "must-not-be-accepted",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "metadata.json")
			encoded, err := json.Marshal(testCase.data)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := NewFileStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("Load accepted unsupported metadata")
			}
		})
	}
}

func TestFileStoreRejectsSymlinksAndPermissivePaths(t *testing.T) {
	t.Run("metadata symlink", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(directory, "target.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "metadata.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileStore(link)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("Load followed metadata symlink")
		}
	})

	t.Run("parent symlink", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDirectory := filepath.Join(root, "link")
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileStore(filepath.Join(linkDirectory, "metadata.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(emptySnapshot()); err == nil {
			t.Fatal("Save followed parent-directory symlink")
		}
	})

	t.Run("intermediate symlink", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		realDirectory := filepath.Join(root, "real")
		if err := os.MkdirAll(
			filepath.Join(realDirectory, "metadata"),
			0o700,
		); err != nil {
			t.Fatal(err)
		}
		linkDirectory := filepath.Join(root, "link")
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileStore(
			filepath.Join(linkDirectory, "metadata", "metadata.json"),
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(emptySnapshot()); err == nil {
			t.Fatal("Save followed intermediate directory symlink")
		}
	})

	t.Run("permissive parent", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(root, "metadata")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		store, err := NewFileStore(filepath.Join(directory, "metadata.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(emptySnapshot()); err == nil {
			t.Fatal("Save accepted group/world-accessible metadata directory")
		}
	})

	t.Run("missing parent", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(root, "not-created")
		store, err := NewFileStore(filepath.Join(directory, "metadata.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(emptySnapshot()); err == nil {
			t.Fatal("Save created an unprovisioned metadata directory")
		}
		if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("metadata directory stat error = %v, want not-exist", err)
		}
	})
}

func TestFileStoreNeverPersistsPrivateCanary(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metadata.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := emptySnapshot()
	snapshot.Revision = 1
	canary := []byte("PRIVATE-KEY-CANARY-DO-NOT-PERSIST")
	assertNoPrivateMaterial(t, snapshot, canary)
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, canary) {
		t.Fatal("metadata file contains private-key canary")
	}
}

func TestFileStoreRejectsInvalidSaveEnvelope(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(filepath.Join(dir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = store.Save(Snapshot{Version: MetadataVersion + 1, Roles: map[Role]RoleState{}})
	if err == nil {
		t.Fatal("Save accepted an unknown metadata version")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Save error = %v, want schema error", err)
	}
}

func TestFileStoreRejectsNestedExclusiveTransaction(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(filepath.Join(dir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- store.withExclusive(
			context.Background(),
			func(s Store) error {
				close(acquired)
				<-release
				return nil
			},
		)
	}()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("outer exclusive transaction did not acquire")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := store.withExclusive(ctx, func(Store) error {
		t.Fatal("concurrent exclusive transaction should not execute")
		return nil
	}); err == nil {
		t.Fatal("concurrent exclusive transaction should return an error")
	}
	close(release)
	select {
	case err := <-holderDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("outer exclusive transaction did not release")
	}
}

func TestFileStoreCrashPartialRecoveryCleansPendingWithoutTPMHandle(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metadata.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	handleA := tpm.Handle(0x81010001)
	handleB := tpm.Handle(0x81010002)
	policy := caPolicy(
		RoleDeviceRootCA,
		tpm.AlgorithmECDSAP256,
		handleA,
		handleB,
	)
	template, err := tpm.SigningTemplate(tpm.AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := emptySnapshot()
	snapshot.Revision = 1
	snapshot.Pending[RoleDeviceRootCA] = KeyMetadata{
		Role:         RoleDeviceRootCA,
		Purpose:      PurposeCertificateAuthority,
		Algorithm:    tpm.AlgorithmECDSAP256,
		Handle:       handleA,
		PublicName:   []byte("orphaned-name"),
		PublicKeyDER: []byte("orphaned-key"),
		Template:     template,
		CreatedAt:    time.Now(),
		Generation:   1,
	}
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}

	backend := newFakeBackend()
	backend.deleteHandle(handleA)
	backend.deleteHandle(handleB)

	manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Open(context.Background()); err != nil {
		t.Fatalf("Open after crash-partial state: %v", err)
	}

	snap, err := manager.PublicSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := snap.Pending[RoleDeviceRootCA]; exists {
		t.Fatal("pending creation should have been cleaned up after crash recovery")
	}
}

func TestFileStoreCrashPartialRecoveryAdoptsExistingPending(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metadata.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	backend := newFakeBackend()
	handle := tpm.Handle(0x81010002)
	otherHandle := tpm.Handle(0x81010003)
	policy := caPolicy(
		RoleDeviceRootCA,
		tpm.AlgorithmECDSAP256,
		handle,
		otherHandle,
	)
	template, err := tpm.SigningTemplate(tpm.AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := generateFakeSigner(tpm.AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	public, err := fakePublic(handle, template, signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := tpm.CanonicalPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := emptySnapshot()
	snapshot.Revision = 1
	snapshot.Pending[RoleDeviceRootCA] = KeyMetadata{
		Role:         RoleDeviceRootCA,
		Purpose:      PurposeCertificateAuthority,
		Algorithm:    tpm.AlgorithmECDSAP256,
		Handle:       handle,
		PublicName:   public.Name,
		PublicKeyDER: publicDER,
		Template:     template,
		CreatedAt:    time.Now(),
		Generation:   1,
	}
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}

	// TPM object exists, so recovery should adopt the pending creation.
	backend.mu.Lock()
	backend.objects[handle] = fakeObject{public: public}
	backend.mu.Unlock()

	manager, err := NewManager(backend, store, []RolePolicy{policy}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Open(context.Background()); err != nil {
		t.Fatalf("Open crash-recovery adopt: %v", err)
	}

	snap, err := manager.PublicSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := snap.Pending[RoleDeviceRootCA]; exists {
		t.Fatal("pending creation should have been adopted")
	}
	state, exists := snap.Roles[RoleDeviceRootCA]
	if !exists {
		t.Fatal("role should be active after crash-recovery adopt")
	}
	if state.Active.Handle != handle {
		t.Fatalf("active handle = %#x, want %#x", uint32(state.Active.Handle), uint32(handle))
	}
}
