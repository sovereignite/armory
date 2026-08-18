// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/sovereignite/anchor"
)

func TestParseModePreservesSystemdCLIContract(t *testing.T) {
	testCases := []struct {
		name      string
		arguments []string
		want      string
		wantError bool
	}{
		{name: "long-running service", want: "run"},
		{name: "first boot", arguments: []string{"initialize"}, want: "initialize"},
		{name: "unknown", arguments: []string{"export"}, wantError: true},
		{name: "too many", arguments: []string{"initialize", "extra"}, wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := parseMode(testCase.arguments)
			if (err != nil) != testCase.wantError {
				t.Fatalf("parseMode error = %v, wantError %t", err, testCase.wantError)
			}
			if actual != testCase.want {
				t.Fatalf("parseMode = %q, want %q", actual, testCase.want)
			}
		})
	}
}

func TestRunFailsClosedWhenHardwareAdapterIsUnavailable(t *testing.T) {
	original := openTPM
	openTPM = func(tpm.GoTPMConfig) (tpm.Backend, error) {
		return nil, tpm.ErrAdapterUnavailable
	}
	t.Cleanup(func() {
		openTPM = original
	})
	for _, arguments := range [][]string{nil, {"initialize"}} {
		var stderr bytes.Buffer
		err := run(arguments, &stderr)
		if !errors.Is(err, tpm.ErrAdapterUnavailable) {
			t.Fatalf("run(%v) error = %v, want adapter unavailable", arguments, err)
		}
	}
}

func TestRunRejectsUnknownCommandBeforeOpeningTPM(t *testing.T) {
	var stderr bytes.Buffer
	err := run([]string{"export"}, &stderr)
	if err == nil {
		t.Fatal("run accepted an export command")
	}
	if errors.Is(err, tpm.ErrAdapterUnavailable) {
		t.Fatal("run opened TPM before rejecting unknown command")
	}
}
