// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sovereignite/anchor"
)

func TestIssueCertificateUsesPurposeScopedTPMSigner(t *testing.T) {
	testCases := []struct {
		name      string
		role      Role
		algorithm tpm.Algorithm
	}{
		{name: "RSA-4096", role: "rsa-cert-ca", algorithm: tpm.AlgorithmRSA4096},
		{name: "ECDSA-P256", role: "ecdsa-cert-ca", algorithm: tpm.AlgorithmECDSAP256},
		{name: "Ed25519", role: "ed25519-cert-ca", algorithm: tpm.AlgorithmEd25519},
	}

	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := newFakeBackend()
			store := newMemoryStore()
			now := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
			clock := &fakeClock{now: now}
			handle := tpm.PersistentHandleFirst + tpm.Handle(200+index*2)
			policy := caPolicy(
				testCase.role,
				testCase.algorithm,
				handle,
				handle+1,
			)
			authorizeCalls := 0
			certificatePolicy := CertificatePolicyFunc(func(
				_ context.Context,
				request CertificateRequest,
			) error {
				authorizeCalls++
				if request.Profile != "device-leaf" {
					return errors.New("profile denied")
				}
				if request.Template.IsCA {
					return errors.New("CA template denied")
				}
				return nil
			})
			manager, err := NewManager(
				backend,
				store,
				[]RolePolicy{policy},
				certificatePolicy,
				clock,
			)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := manager.EnsureRole(context.Background(), testCase.role)
			if err != nil {
				t.Fatal(err)
			}
			parent, template, subjectPublic := certificateInputs(t, metadata, now)
			certificateDER, err := manager.IssueCertificate(
				context.Background(),
				CertificateRequest{
					Role:             testCase.role,
					Profile:          "device-leaf",
					Template:         template,
					Parent:           parent,
					SubjectPublicKey: subjectPublic,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := x509.ParseCertificate(certificateDER)
			if err != nil {
				t.Fatal(err)
			}
			tbs := certificate.RawTBSCertificate
			sig := certificate.Signature
			var verifyErr error
			switch pub := parent.PublicKey.(type) {
			case ed25519.PublicKey:
				if !ed25519.Verify(pub, tbs, sig) {
					verifyErr = errors.New("ed25519 signature verification failed")
				}
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pub, sha256Hash(tbs), sig) {
					verifyErr = errors.New("ecdsa signature verification failed")
				}
			case *rsa.PublicKey:
				verifyErr = rsa.VerifyPKCS1v15(pub, crypto.SHA256, sha256Hash(tbs), sig)
			default:
				t.Fatalf("unsupported parent public key type %T", parent.PublicKey)
			}
			if verifyErr != nil {
				t.Fatalf("certificate signature: %v", verifyErr)
			}
			if authorizeCalls != 1 {
				t.Fatalf("authorize calls = %d, want 1", authorizeCalls)
			}
			if backend.signCalls != 1 || len(backend.signRequests) != 1 {
				t.Fatalf(
					"TPM sign calls = %d requests = %d, want one",
					backend.signCalls,
					len(backend.signRequests),
				)
			}
			signRequest := backend.signRequests[0]
			if signRequest.Purpose != tpm.SignPurposeCertificate ||
				signRequest.Object.Handle != metadata.Handle ||
				signRequest.Object.Template != metadata.Template {
				t.Fatalf("TPM sign request escaped certificate scope: %#v", signRequest)
			}
		})
	}
}

func TestIssueCertificateWaitsForInFlightPersistentCreation(t *testing.T) {
	backend := newFakeBackend()
	store := newMemoryStore()
	now := time.Now().UTC()
	role := Role("transaction-cert-ca")
	handle := tpm.PersistentHandleFirst + 210
	manager, err := NewManager(
		backend,
		store,
		[]RolePolicy{caPolicy(
			role,
			tpm.AlgorithmECDSAP256,
			handle,
			handle+1,
		)},
		CertificatePolicyFunc(func(
			context.Context,
			CertificateRequest,
		) error {
			return nil
		}),
		&fakeClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared := make(chan struct{})
	continuePersistence := make(chan struct{})
	backend.afterPrepare = func() {
		close(prepared)
		<-continuePersistence
	}
	type ensureResult struct {
		metadata KeyMetadata
		err      error
	}
	ensured := make(chan ensureResult, 1)
	go func() {
		metadata, ensureErr := manager.EnsureRole(context.Background(), role)
		ensured <- ensureResult{metadata: metadata, err: ensureErr}
	}()
	select {
	case <-prepared:
	case <-time.After(5 * time.Second):
		t.Fatal("persistent creation did not reach its prepared intent")
	}
	pendingSnapshot, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	pending, exists := pendingSnapshot.Pending[role]
	if !exists {
		t.Fatal("prepared persistence had no durable pending metadata")
	}
	parent, template, subjectPublic := certificateInputs(t, pending, now)
	issued := make(chan error, 1)
	go func() {
		_, issueErr := manager.IssueCertificate(
			context.Background(),
			CertificateRequest{
				Role:             role,
				Profile:          "device-leaf",
				Template:         template,
				Parent:           parent,
				SubjectPublicKey: subjectPublic,
			},
		)
		issued <- issueErr
	}()
	select {
	case issueErr := <-issued:
		t.Fatalf(
			"IssueCertificate escaped an in-flight persistence transaction: %v",
			issueErr,
		)
	case <-time.After(100 * time.Millisecond):
	}
	close(continuePersistence)
	select {
	case result := <-ensured:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.metadata.Handle != handle {
			t.Fatalf("created handle = %#x, want %#x", result.metadata.Handle, handle)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("persistent creation did not finish")
	}
	select {
	case issueErr := <-issued:
		if issueErr != nil {
			t.Fatal(issueErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("IssueCertificate remained blocked after creation")
	}
}

func TestIssueCertificateFailsClosedWithoutPolicy(t *testing.T) {
	backend := newFakeBackend()
	now := time.Now().UTC()
	policy := caPolicy(
		RoleDeviceRootCA,
		tpm.AlgorithmECDSAP256,
		tpm.PersistentHandleFirst+220,
		tpm.PersistentHandleFirst+221,
	)
	manager, err := NewManager(
		backend,
		newMemoryStore(),
		[]RolePolicy{policy},
		nil,
		&fakeClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA)
	if err != nil {
		t.Fatal(err)
	}
	parent, template, subjectPublic := certificateInputs(t, metadata, now)
	_, err = manager.IssueCertificate(context.Background(), CertificateRequest{
		Role:             RoleDeviceRootCA,
		Profile:          "device-leaf",
		Template:         template,
		Parent:           parent,
		SubjectPublicKey: subjectPublic,
	})
	if !errors.Is(err, ErrCertificatePolicyUnavailable) {
		t.Fatalf("IssueCertificate error = %v, want missing policy", err)
	}
	if backend.signCalls != 0 {
		t.Fatalf("TPM sign calls = %d, want 0", backend.signCalls)
	}
}

func TestIssueCertificatePolicyDenialDoesNotReachTPM(t *testing.T) {
	backend := newFakeBackend()
	now := time.Now().UTC()
	policy := caPolicy(
		RoleDeviceRootCA,
		tpm.AlgorithmECDSAP256,
		tpm.PersistentHandleFirst+230,
		tpm.PersistentHandleFirst+231,
	)
	manager, err := NewManager(
		backend,
		newMemoryStore(),
		[]RolePolicy{policy},
		CertificatePolicyFunc(func(
			context.Context,
			CertificateRequest,
		) error {
			return errors.New("injected profile denial")
		}),
		&fakeClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA)
	if err != nil {
		t.Fatal(err)
	}
	parent, template, subjectPublic := certificateInputs(t, metadata, now)
	if _, err := manager.IssueCertificate(
		context.Background(),
		CertificateRequest{
			Role:             RoleDeviceRootCA,
			Profile:          "device-leaf",
			Template:         template,
			Parent:           parent,
			SubjectPublicKey: subjectPublic,
		},
	); err == nil {
		t.Fatal("IssueCertificate succeeded despite policy denial")
	}
	if backend.signCalls != 0 {
		t.Fatalf("TPM sign calls = %d, want 0", backend.signCalls)
	}
}

func TestIssueCertificatePolicyCanReenterManager(t *testing.T) {
	backend := newFakeBackend()
	now := time.Now().UTC()
	policy := caPolicy(
		RoleDeviceRootCA,
		tpm.AlgorithmECDSAP256,
		tpm.PersistentHandleFirst+235,
		tpm.PersistentHandleFirst+236,
	)
	var manager *Manager
	certificatePolicy := CertificatePolicyFunc(func(
		ctx context.Context,
		_ CertificateRequest,
	) error {
		_, err := manager.Metadata(ctx, RoleDeviceRootCA)
		return err
	})
	var err error
	manager, err = NewManager(
		backend,
		newMemoryStore(),
		[]RolePolicy{policy},
		certificatePolicy,
		&fakeClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA)
	if err != nil {
		t.Fatal(err)
	}
	parent, template, subjectPublic := certificateInputs(t, metadata, now)
	done := make(chan error, 1)
	go func() {
		_, issueErr := manager.IssueCertificate(
			context.Background(),
			CertificateRequest{
				Role:             RoleDeviceRootCA,
				Profile:          "device-leaf",
				Template:         template,
				Parent:           parent,
				SubjectPublicKey: subjectPublic,
			},
		)
		done <- issueErr
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IssueCertificate deadlocked while policy reentered Manager")
	}
}

func TestIssueCertificateRechecksHandleImmediatelyBeforeSigning(t *testing.T) {
	backend := newFakeBackend()
	now := time.Now().UTC()
	policy := caPolicy(
		RoleDeviceRootCA,
		tpm.AlgorithmECDSAP256,
		tpm.PersistentHandleFirst+240,
		tpm.PersistentHandleFirst+241,
	)
	manager, err := NewManager(
		backend,
		newMemoryStore(),
		[]RolePolicy{policy},
		CertificatePolicyFunc(func(context.Context, CertificateRequest) error {
			return nil
		}),
		&fakeClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.EnsureRole(context.Background(), RoleDeviceRootCA)
	if err != nil {
		t.Fatal(err)
	}
	parent, template, subjectPublic := certificateInputs(t, metadata, now)
	manager.certificatePolicy = CertificatePolicyFunc(func(
		context.Context,
		CertificateRequest,
	) error {
		backend.replaceName(metadata.Handle, []byte("replacement"))
		return nil
	})
	if _, err := manager.IssueCertificate(
		context.Background(),
		CertificateRequest{
			Role:             RoleDeviceRootCA,
			Profile:          "device-leaf",
			Template:         template,
			Parent:           parent,
			SubjectPublicKey: subjectPublic,
		},
	); !errors.Is(err, ErrMetadataMismatch) {
		t.Fatalf("IssueCertificate error = %v, want metadata mismatch", err)
	}
	if backend.signCalls != 0 {
		t.Fatalf("TPM sign calls = %d, want 0", backend.signCalls)
	}
}

func TestCloneCertificateRequestDeepCopiesMutableFields(t *testing.T) {
	subjectPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parentPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectFirst := subjectPublic[0]
	parentFirst := parentPublic[0]
	request := CertificateRequest{
		Role:    RoleDeviceRootCA,
		Profile: "deep-copy",
		Template: &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject: pkix.Name{
				CommonName: "original",
				Names: []pkix.AttributeTypeAndValue{{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
					Value: []byte("attribute"),
				}},
			},
			DNSNames: []string{"original.test"},
			PermittedIPRanges: []*net.IPNet{{
				IP:   net.IP{10, 0, 0, 0},
				Mask: net.IPMask{255, 0, 0, 0},
			}},
			SubjectKeyId: []byte{1, 2, 3},
		},
		Parent: &x509.Certificate{
			SerialNumber: big.NewInt(8),
			PublicKey:    parentPublic,
		},
		SubjectPublicKey: subjectPublic,
	}
	cloned, err := cloneCertificateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	cloned.Template.SerialNumber.SetInt64(99)
	cloned.Template.Subject.Names[0].Type[0] = 9
	cloned.Template.Subject.Names[0].Value.([]byte)[0] = 'X'
	cloned.Template.DNSNames[0] = "mutated.test"
	cloned.Template.PermittedIPRanges[0].IP[0] = 192
	cloned.Template.PermittedIPRanges[0].Mask[0] = 0
	cloned.Template.SubjectKeyId[0] = 9
	cloned.SubjectPublicKey.(ed25519.PublicKey)[0] ^= 0xff
	cloned.Parent.PublicKey.(ed25519.PublicKey)[0] ^= 0xff

	attribute := request.Template.Subject.Names[0]
	if request.Template.SerialNumber.Int64() != 7 ||
		attribute.Type[0] != 2 ||
		attribute.Value.([]byte)[0] != 'a' ||
		request.Template.DNSNames[0] != "original.test" ||
		request.Template.PermittedIPRanges[0].IP[0] != 10 ||
		request.Template.PermittedIPRanges[0].Mask[0] != 255 ||
		request.Template.SubjectKeyId[0] != 1 ||
		request.SubjectPublicKey.(ed25519.PublicKey)[0] != subjectFirst ||
		request.Parent.PublicKey.(ed25519.PublicKey)[0] != parentFirst {
		t.Fatal("mutating certificate authorization copy changed the operation request")
	}

	request.Template.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{
		Type: asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: &asn1.RawValue{
			Tag:   asn1.TagOctetString,
			Bytes: []byte("shared-pointer"),
		},
	}}
	if _, err := cloneCertificateRequest(request); err == nil {
		t.Fatal("certificate copy accepted an unsupported pointer-valued ASN.1 attribute")
	}

	cyclic := make([]any, 1)
	cyclic[0] = cyclic
	request.Template.Subject.ExtraNames[0].Value = cyclic
	if _, err := cloneCertificateRequest(request); err == nil {
		t.Fatal("certificate copy accepted a recursive ASN.1 attribute value")
	}
}

func TestLifetimeIdentityCannotIssueCertificate(t *testing.T) {
	backend := newFakeBackend()
	now := time.Now().UTC()
	policy := identityPolicy(
		tpm.AlgorithmEd25519,
		tpm.PersistentHandleFirst+250,
	)
	manager, err := NewManager(
		backend,
		newMemoryStore(),
		[]RolePolicy{policy},
		CertificatePolicyFunc(func(context.Context, CertificateRequest) error {
			return nil
		}),
		&fakeClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.EnsureRole(context.Background(), RoleDeviceIPNSIdentity)
	if err != nil {
		t.Fatal(err)
	}
	parent, template, subjectPublic := certificateInputs(t, metadata, now)
	_, err = manager.IssueCertificate(context.Background(), CertificateRequest{
		Role:             RoleDeviceIPNSIdentity,
		Profile:          "device-leaf",
		Template:         template,
		Parent:           parent,
		SubjectPublicKey: subjectPublic,
	})
	if !errors.Is(err, ErrCertificatePurposeDenied) {
		t.Fatalf("IssueCertificate error = %v, want purpose denial", err)
	}
	if backend.signCalls != 0 {
		t.Fatalf("TPM sign calls = %d, want 0", backend.signCalls)
	}
}

func certificateInputs(
	t *testing.T,
	metadata KeyMetadata,
	now time.Time,
) (*x509.Certificate, *x509.Certificate, ed25519.PublicKey) {
	t.Helper()
	parentPublic, err := publicKeyFromMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sovereignite test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             parentPublic,
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "device.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"device.test"},
	}
	subjectPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return parent, template, subjectPublic
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
