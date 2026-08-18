// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package armory

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maximumMetadataBytes = 4 << 20

// FileStore atomically replaces one versioned public-metadata document.
type FileStore struct {
	path            string
	lock            *fileStoreLock
	transactionRoot *os.Root
}

var fileStoreLocks sync.Map

type fileStoreLock struct {
	token chan struct{}
}

func newFileStoreLock() *fileStoreLock {
	lock := &fileStoreLock{token: make(chan struct{}, 1)}
	lock.token <- struct{}{}
	return lock
}

func (l *fileStoreLock) acquire(ctx context.Context) error {
	if l == nil {
		return errors.New("metadata process lock is unavailable")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.token:
		return nil
	}
}

func (l *fileStoreLock) release() {
	if l != nil {
		l.token <- struct{}{}
	}
}

// NewFileStore creates a public-metadata store rooted at an absolute path.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("metadata path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve metadata path: %w", err)
	}
	lockValue, _ := fileStoreLocks.LoadOrStore(absolute, newFileStoreLock())
	return &FileStore{
		path: absolute,
		lock: lockValue.(*fileStoreLock),
	}, nil
}

// Load reads and strictly validates the public-metadata envelope. A missing
// file represents an empty version-one store.
func (s *FileStore) Load() (Snapshot, error) {
	if s == nil || s.path == "" || s.lock == nil {
		return Snapshot{}, errors.New("metadata store is not configured")
	}
	if s.transactionRoot != nil {
		return loadSnapshotFromRoot(s.transactionRoot, filepath.Base(s.path))
	}
	if err := s.lock.acquire(context.Background()); err != nil {
		return Snapshot{}, err
	}
	defer s.lock.release()
	root, err := openPrivateMetadataRoot(filepath.Dir(s.path))
	if err != nil {
		return Snapshot{}, err
	}
	defer func() { _ = root.Close() }()
	directoryLock, err := lockMetadataRoot(
		context.Background(),
		root,
		syscall.LOCK_SH,
	)
	if err != nil {
		return Snapshot{}, err
	}
	defer unlockMetadataRoot(directoryLock)
	return loadSnapshotFromRoot(root, filepath.Base(s.path))
}

func loadSnapshotFromRoot(root *os.Root, base string) (Snapshot, error) {
	file, info, err := openSecureRegularFile(root, base)
	if errors.Is(err, os.ErrNotExist) {
		return emptySnapshot(), nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	if info.Size() > maximumMetadataBytes {
		return Snapshot{}, fmt.Errorf(
			"metadata file is %d bytes, limit is %d",
			info.Size(),
			maximumMetadataBytes,
		)
	}
	defer func() { _ = file.Close() }()

	decoder := json.NewDecoder(io.LimitReader(file, maximumMetadataBytes+1))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Snapshot{}, errors.New("metadata contains multiple JSON values")
		}
		return Snapshot{}, fmt.Errorf("decode trailing metadata: %w", err)
	}
	if err := validateSnapshotEnvelope(snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Pending == nil {
		snapshot.Pending = make(map[Role]KeyMetadata)
	}
	return cloneSnapshot(snapshot), nil
}

// Save durably writes a complete public snapshot to a same-directory temporary
// file and atomically renames it into place.
func (s *FileStore) Save(snapshot Snapshot) error {
	if s == nil || s.path == "" || s.lock == nil {
		return errors.New("metadata store is not configured")
	}
	if err := validateSnapshotEnvelope(snapshot); err != nil {
		return err
	}
	if s.transactionRoot != nil {
		return saveSnapshotToRoot(
			s.transactionRoot,
			filepath.Base(s.path),
			snapshot,
		)
	}
	if err := s.lock.acquire(context.Background()); err != nil {
		return err
	}
	defer s.lock.release()
	root, err := openPrivateMetadataRoot(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	directoryLock, err := lockMetadataRoot(
		context.Background(),
		root,
		syscall.LOCK_EX,
	)
	if err != nil {
		return err
	}
	defer unlockMetadataRoot(directoryLock)
	return saveSnapshotToRoot(root, filepath.Base(s.path), snapshot)
}

func saveSnapshotToRoot(
	root *os.Root,
	base string,
	snapshot Snapshot,
) error {
	current, err := loadSnapshotFromRoot(root, base)
	if err != nil {
		return err
	}
	if current.Revision == math.MaxUint64 ||
		snapshot.Revision != current.Revision+1 {
		return fmt.Errorf(
			"%w: current revision %d, replacement revision %d",
			ErrMetadataRevisionConflict,
			current.Revision,
			snapshot.Revision,
		)
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumMetadataBytes {
		return fmt.Errorf(
			"encoded metadata is %d bytes, limit is %d",
			len(encoded),
			maximumMetadataBytes,
		)
	}

	temporary, temporaryName, err := createRootedTemporary(root, base)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temporaryName) }()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set metadata permissions: %w", err)
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write metadata: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync metadata: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close metadata: %w", err)
	}
	if err := root.Rename(temporaryName, base); err != nil {
		return fmt.Errorf("replace metadata: %w", err)
	}
	directoryFile, err := root.Open(".")
	if err != nil {
		return errors.Join(
			ErrMetadataDurabilityUncertain,
			fmt.Errorf("open metadata directory for sync: %w", err),
		)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil {
		return errors.Join(
			ErrMetadataDurabilityUncertain,
			fmt.Errorf("sync metadata directory: %w", syncErr),
		)
	}
	if closeErr != nil {
		return errors.Join(
			ErrMetadataDurabilityUncertain,
			fmt.Errorf("close metadata directory: %w", closeErr),
		)
	}
	return nil
}

// withExclusive serializes a complete key-manager mutation, including its TPM
// side effects, against every cooperating process that uses this metadata
// directory. The callback receives a view that reuses the held directory lock
// instead of attempting to lock it recursively.
func (s *FileStore) withExclusive(
	ctx context.Context,
	operation func(Store) error,
) error {
	if s == nil || s.path == "" || s.lock == nil {
		return errors.New("metadata store is not configured")
	}
	if operation == nil {
		return errors.New("metadata transaction operation is required")
	}
	if s.transactionRoot != nil {
		return errors.New("nested metadata transactions are not allowed")
	}
	if err := s.lock.acquire(ctx); err != nil {
		return err
	}
	defer s.lock.release()
	root, err := openPrivateMetadataRoot(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	directoryLock, err := lockMetadataRoot(ctx, root, syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlockMetadataRoot(directoryLock)
	transaction := &FileStore{
		path:            s.path,
		lock:            s.lock,
		transactionRoot: root,
	}
	return operation(transaction)
}

func lockMetadataRoot(
	ctx context.Context,
	root *os.Root,
	operation int,
) (*os.File, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open metadata directory for locking: %w", err)
	}
	for {
		err := syscall.Flock(int(directory.Fd()), operation|syscall.LOCK_NB)
		if err == nil {
			return directory, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) &&
			!errors.Is(err, syscall.EAGAIN) {
			_ = directory.Close()
			return nil, fmt.Errorf("lock metadata directory: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = directory.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func unlockMetadataRoot(directory *os.File) {
	if directory == nil {
		return
	}
	_ = syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
	_ = directory.Close()
}

func openPrivateMetadataRoot(path string) (*os.Root, error) {
	absolute, err := resolveTrustedRootSymlink(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(absolute)
	rootPath := volume + string(os.PathSeparator)
	relative := strings.TrimPrefix(absolute, rootPath)
	components := strings.Split(relative, string(os.PathSeparator))
	if relative == "" {
		return nil, errors.New("metadata directory cannot be the filesystem root")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for metadata: %w", err)
	}
	for index, component := range components {
		if component == "" {
			continue
		}
		info, err := root.Lstat(component)
		if err != nil {
			_ = root.Close()
			return nil, fmt.Errorf(
				"inspect metadata directory component %q: %w",
				component,
				err,
			)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			_ = root.Close()
			return nil, fmt.Errorf(
				"metadata directory component %q is not a real directory",
				component,
			)
		}
		next, err := root.OpenRoot(component)
		if err != nil {
			_ = root.Close()
			return nil, fmt.Errorf(
				"open metadata directory component %q: %w",
				component,
				err,
			)
		}
		openedDirectory, err := next.Open(".")
		if err != nil {
			_ = next.Close()
			_ = root.Close()
			return nil, fmt.Errorf(
				"open rooted metadata directory component %q: %w",
				component,
				err,
			)
		}
		opened, statErr := openedDirectory.Stat()
		closeErr := openedDirectory.Close()
		if statErr != nil || closeErr != nil || !os.SameFile(info, opened) {
			_ = next.Close()
			_ = root.Close()
			if statErr != nil {
				return nil, fmt.Errorf(
					"stat rooted metadata directory component %q: %w",
					component,
					statErr,
				)
			}
			if closeErr != nil {
				return nil, fmt.Errorf(
					"close rooted metadata directory component %q: %w",
					component,
					closeErr,
				)
			}
			return nil, fmt.Errorf(
				"metadata directory component %q changed while it was opened",
				component,
			)
		}
		if err := root.Close(); err != nil {
			_ = next.Close()
			return nil, fmt.Errorf(
				"close parent of metadata directory component %q: %w",
				component,
				err,
			)
		}
		root = next
		if index == len(components)-1 {
			if err := validatePrivateDirectoryInfo(opened); err != nil {
				_ = root.Close()
				return nil, err
			}
		}
	}
	return root, nil
}

func openSecureRegularFile(
	root *os.Root,
	name string,
) (*os.File, os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, errors.New("metadata path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf(
			"metadata file permissions %04o allow group or other access",
			info.Mode().Perm(),
		)
	}
	if err := validateCurrentOwner("metadata file", info); err != nil {
		return nil, nil, err
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("open metadata: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat opened metadata: %w", err)
	}
	if !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, errors.New("metadata file changed while it was opened")
	}
	return file, opened, nil
}

func createRootedTemporary(
	root *os.Root,
	base string,
) (*os.File, string, error) {
	for attempts := 0; attempts < 32; attempts++ {
		random := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			return nil, "", fmt.Errorf("generate metadata temporary name: %w", err)
		}
		name := "." + base + ".tmp-" + hex.EncodeToString(random)
		file, err := root.OpenFile(
			name,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			0o600,
		)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", fmt.Errorf("create metadata temporary file: %w", err)
		}
	}
	return nil, "", errors.New("exhausted metadata temporary-name attempts")
}

func validatePrivateDirectoryInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("metadata parent is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"metadata directory permissions %04o allow group or other access",
			info.Mode().Perm(),
		)
	}
	return validateCurrentOwner("metadata directory", info)
}

func validateCurrentOwner(label string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s ownership is unavailable", label)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf(
			"%s owner %d does not match effective user %d",
			label,
			stat.Uid,
			os.Geteuid(),
		)
	}
	return nil
}

func resolveTrustedRootSymlink(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve metadata directory: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	rootPath := volume + string(os.PathSeparator)
	relative := strings.TrimPrefix(absolute, rootPath)
	components := strings.Split(relative, string(os.PathSeparator))
	firstIndex := -1
	for index, component := range components {
		if component != "" {
			firstIndex = index
			break
		}
	}
	if firstIndex < 0 {
		return absolute, nil
	}
	firstPath := filepath.Join(rootPath, components[firstIndex])
	info, err := os.Lstat(firstPath)
	if err != nil {
		return "", fmt.Errorf("inspect metadata root component %q: %w", firstPath, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return absolute, nil
	}
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		return "", fmt.Errorf("inspect filesystem root %q: %w", rootPath, err)
	}
	linkStat, linkOK := info.Sys().(*syscall.Stat_t)
	rootStat, rootOK := rootInfo.Sys().(*syscall.Stat_t)
	if !linkOK ||
		!rootOK ||
		linkStat.Uid != 0 ||
		rootStat.Uid != 0 ||
		rootInfo.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf(
			"metadata root component %q is an untrusted symbolic link",
			firstPath,
		)
	}
	target, err := os.Readlink(firstPath)
	if err != nil {
		return "", fmt.Errorf("read trusted metadata root link %q: %w", firstPath, err)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(rootPath, target)
	}
	remainder := components[firstIndex+1:]
	resolved := filepath.Clean(filepath.Join(append([]string{target}, remainder...)...))
	resolvedVolume := filepath.VolumeName(resolved)
	resolvedRoot := resolvedVolume + string(os.PathSeparator)
	if !filepath.IsAbs(resolved) ||
		resolvedRoot != rootPath ||
		resolved == rootPath {
		return "", fmt.Errorf(
			"trusted metadata root link %q has invalid target %q",
			firstPath,
			target,
		)
	}
	return resolved, nil
}

func validateSnapshotEnvelope(snapshot Snapshot) error {
	if snapshot.Version != MetadataVersion {
		return fmt.Errorf(
			"unsupported metadata version %d, expected %d",
			snapshot.Version,
			MetadataVersion,
		)
	}
	if snapshot.Roles == nil {
		return errors.New("metadata roles object is missing")
	}
	return nil
}
