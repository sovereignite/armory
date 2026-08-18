// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sovereignite/keymanager"
	"github.com/sovereignite/tpm"
)

const (
	defaultTPMDevice    = "/dev/tpmrm0"
	defaultMetadataPath = "/var/lib/sovereignite/keymanager/metadata.json"
)

var openTPM = tpm.OpenGoTPM

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		slog.Error("key manager stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("sovereignite-keymanager", flag.ContinueOnError)
	flags.SetOutput(stderr)
	devicePath := flags.String(
		"tpm-device",
		defaultTPMDevice,
		"explicit Linux TPM resource-manager device",
	)
	metadataPath := flags.String(
		"metadata-path",
		defaultMetadataPath,
		"path to the public-metadata JSON file",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	mode, err := parseMode(flags.Args())
	if err != nil {
		return err
	}
	backend, err := openTPM(tpm.GoTPMConfig{
		DevicePath: strings.TrimSpace(*devicePath),
	})
	if err != nil {
		return fmt.Errorf("%s: open TPM: %w", mode, err)
	}
	defer func() { _ = backend.Close() }()

	store, err := keymanager.NewFileStore(strings.TrimSpace(*metadataPath))
	if err != nil {
		return fmt.Errorf("%s: create metadata store: %w", mode, err)
	}
	policies := keymanager.DefaultPolicies()
	// A nil CertificatePolicy fails closed: all IssueCertificate calls return
	// ErrCertificatePolicyUnavailable. Replace with an authorized profile
	// policy before production deployment.
	manager, err := keymanager.NewManager(
		backend,
		store,
		policies,
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("%s: create manager: %w", mode, err)
	}

	ctx, cancel := signalContext(context.Background())
	defer cancel()

	switch mode {
	case "initialize":
		results, initErr := manager.Initialize(ctx)
		if initErr != nil {
			return fmt.Errorf("initialize: %w", initErr)
		}
		for _, metadata := range results {
			slog.Info("initialized role",
				"role", metadata.Role,
				"handle", fmt.Sprintf("%#x", uint32(metadata.Handle)),
				"generation", metadata.Generation,
			)
		}
		return nil
	case "run":
		if err := manager.Open(ctx); err != nil {
			return fmt.Errorf("open: %w", err)
		}
		slog.Info("key manager running", "device", *devicePath)
		<-ctx.Done()
		return ctx.Err()
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}

func parseMode(arguments []string) (string, error) {
	switch len(arguments) {
	case 0:
		return "run", nil
	case 1:
		if arguments[0] == "initialize" {
			return "initialize", nil
		}
		return "", fmt.Errorf("unknown key-manager command %q", arguments[0])
	default:
		return "", errors.New("key manager accepts only the optional initialize command")
	}
}

func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-c:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
