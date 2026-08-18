// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keymanager

import (
	"bytes"
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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sovereignite/tpm"
)

// CertificateRequest is a certificate-only operation. It does not accept a
// digest, raw TBS bytes, private key, TPM handle, or caller-selected signer.
type CertificateRequest struct {
	Role             Role
	Profile          string
	Template         *x509.Certificate
	Parent           *x509.Certificate
	SubjectPublicKey crypto.PublicKey
}

// CertificatePolicy authorizes the project-specific certificate profile before
// the one-shot TPM signer is constructed. A nil policy always fails closed.
type CertificatePolicy interface {
	AuthorizeCertificate(context.Context, CertificateRequest) error
}

// CertificatePolicyFunc adapts a policy function without exposing signing.
type CertificatePolicyFunc func(context.Context, CertificateRequest) error

// AuthorizeCertificate implements CertificatePolicy.
func (f CertificatePolicyFunc) AuthorizeCertificate(
	ctx context.Context,
	request CertificateRequest,
) error {
	if f == nil {
		return ErrCertificatePolicyUnavailable
	}
	return f(ctx, request)
}

// IssueCertificate applies the injected profile policy and invokes
// x509.CreateCertificate with an unexported one-shot crypto.Signer adapter.
func (m *Manager) IssueCertificate(
	ctx context.Context,
	request CertificateRequest,
) ([]byte, error) {
	var operation CertificateRequest
	var metadata KeyMetadata
	var signerPublic crypto.PublicKey
	var certificatePolicy CertificatePolicy
	err := m.withExclusiveOperation(ctx, func() error {
		var prepareErr error
		operation,
			metadata,
			signerPublic,
			certificatePolicy,
			prepareErr = m.prepareCertificateLocked(ctx, request)
		return prepareErr
	})
	if err != nil {
		return nil, err
	}

	authorizationCopy, err := cloneCertificateRequest(operation)
	if err != nil {
		return nil, err
	}
	if err := certificatePolicy.AuthorizeCertificate(ctx, authorizationCopy); err != nil {
		return nil, fmt.Errorf("authorize certificate profile %q: %w", operation.Profile, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var certificateDER []byte
	err = m.withExclusiveOperation(ctx, func() error {
		if err := m.ensureLoadedLocked(ctx); err != nil {
			return err
		}
		state, exists := m.snapshot.Roles[operation.Role]
		if !exists || !sameKeyMetadata(state.Active, metadata) {
			return fmt.Errorf(
				"%w: certificate signer changed after profile authorization",
				ErrMetadataMismatch,
			)
		}
		if err := m.verifyMetadataLocked(ctx, state.Active); err != nil {
			return err
		}

		signer := &certificateSigner{
			ctx:       ctx,
			backend:   m.backend,
			metadata:  cloneKeyMetadata(state.Active),
			publicKey: signerPublic,
		}
		var createErr error
		certificateDER, createErr = x509.CreateCertificate(
			rand.Reader,
			operation.Template,
			operation.Parent,
			operation.SubjectPublicKey,
			signer,
		)
		if createErr != nil {
			return fmt.Errorf("create certificate: %w", createErr)
		}
		certificate, parseErr := x509.ParseCertificate(certificateDER)
		if parseErr != nil {
			return fmt.Errorf("parse created certificate: %w", parseErr)
		}
		if verifyErr := verifyCertificateSignature(
			certificate,
			operation.Parent.PublicKey,
		); verifyErr != nil {
			return fmt.Errorf(
				"verify created TPM-signed certificate: %w",
				verifyErr,
			)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return certificateDER, nil
}

func (m *Manager) prepareCertificateLocked(
	ctx context.Context,
	request CertificateRequest,
) (
	CertificateRequest,
	KeyMetadata,
	crypto.PublicKey,
	CertificatePolicy,
	error,
) {
	if err := m.ensureLoadedLocked(ctx); err != nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, err
	}
	policy, exists := m.policies[request.Role]
	if !exists {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, fmt.Errorf(
			"%w: %q",
			ErrRoleNotConfigured,
			request.Role,
		)
	}
	if policy.Purpose != PurposeCertificateAuthority {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, fmt.Errorf(
			"%w: %q",
			ErrCertificatePurposeDenied,
			request.Role,
		)
	}
	if m.certificatePolicy == nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, ErrCertificatePolicyUnavailable
	}
	state, exists := m.snapshot.Roles[request.Role]
	if !exists {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, fmt.Errorf(
			"key role %q has not been initialized",
			request.Role,
		)
	}
	if err := m.verifyMetadataLocked(ctx, state.Active); err != nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, err
	}

	operation, err := cloneCertificateRequest(request)
	if err != nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, err
	}
	if strings.TrimSpace(operation.Profile) == "" {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, errors.New(
			"certificate profile is required",
		)
	}
	if operation.Template == nil || operation.Parent == nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, errors.New(
			"certificate template and parent are required",
		)
	}
	if operation.SubjectPublicKey == nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, errors.New(
			"certificate subject public key is required",
		)
	}
	if !operation.Parent.BasicConstraintsValid ||
		!operation.Parent.IsCA ||
		operation.Parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, errors.New(
			"certificate parent is not authorized to sign certificates",
		)
	}

	signerPublic, err := x509.ParsePKIXPublicKey(state.Active.PublicKeyDER)
	if err != nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, fmt.Errorf(
			"%w: parse stored signer public key: %v",
			ErrMetadataMismatch,
			err,
		)
	}
	signerPublicDER, err := x509.MarshalPKIXPublicKey(signerPublic)
	if err != nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, fmt.Errorf(
			"marshal signer public key: %w",
			err,
		)
	}
	parentPublicDER, err := x509.MarshalPKIXPublicKey(operation.Parent.PublicKey)
	if err != nil {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, fmt.Errorf(
			"marshal parent public key: %w",
			err,
		)
	}
	if !bytes.Equal(signerPublicDER, parentPublicDER) {
		return CertificateRequest{}, KeyMetadata{}, nil, nil, errors.New(
			"certificate parent does not match the selected TPM CA role",
		)
	}
	return operation,
		cloneKeyMetadata(state.Active),
		signerPublic,
		m.certificatePolicy,
		nil
}

type certificateSigner struct {
	ctx       context.Context
	backend   tpm.Backend
	metadata  KeyMetadata
	publicKey crypto.PublicKey
	used      bool
}

func (s *certificateSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *certificateSigner) Sign(
	_ io.Reader,
	payload []byte,
	options crypto.SignerOpts,
) ([]byte, error) {
	if s.used {
		return nil, errors.New("certificate signer is one-shot")
	}
	s.used = true
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if options == nil {
		return nil, errors.New("certificate signature options are required")
	}
	public, err := s.backend.ReadPublic(s.ctx, s.metadata.Handle)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: re-read certificate signer: %w",
			ErrMetadataMismatch,
			err,
		)
	}
	if err := verifyPublicMetadata(s.metadata, public); err != nil {
		return nil, err
	}

	request := tpm.SignRequest{
		Object:  objectReference(s.metadata),
		Purpose: tpm.SignPurposeCertificate,
		Scheme:  s.metadata.Template.SigningScheme,
		Payload: slices.Clone(payload),
	}
	switch s.metadata.Algorithm {
	case tpm.AlgorithmRSA4096, tpm.AlgorithmECDSAP256:
		if options.HashFunc() != crypto.SHA256 ||
			len(payload) != crypto.SHA256.Size() {
			return nil, errors.New("certificate signer requires an exact SHA-256 digest")
		}
		request.Hash = crypto.SHA256
	case tpm.AlgorithmEd25519:
		if options.HashFunc() != crypto.Hash(0) {
			return nil, errors.New("Ed25519 certificate signer requires the unhashed TBS certificate")
		}
	default:
		return nil, &tpm.UnsupportedCapabilityError{
			Algorithm: s.metadata.Algorithm,
			Reason:    "certificate signing algorithm is not allowlisted",
		}
	}
	signature, err := s.backend.Sign(s.ctx, request)
	if err != nil {
		return nil, fmt.Errorf("TPM certificate signature: %w", err)
	}
	if len(signature) == 0 {
		return nil, errors.New("TPM returned an empty certificate signature")
	}
	return signature, nil
}

func cloneCertificateRequest(request CertificateRequest) (CertificateRequest, error) {
	cloned := request
	var err error
	cloned.Template, err = cloneCertificate(request.Template)
	if err != nil {
		return CertificateRequest{}, fmt.Errorf("copy certificate template: %w", err)
	}
	cloned.Parent, err = cloneCertificate(request.Parent)
	if err != nil {
		return CertificateRequest{}, fmt.Errorf("copy certificate parent: %w", err)
	}
	if request.Template != nil && request.Template.PublicKey != nil {
		publicKey, err := clonePublicKey(request.Template.PublicKey)
		if err != nil {
			return CertificateRequest{}, fmt.Errorf("copy template public key: %w", err)
		}
		cloned.Template.PublicKey = publicKey
	}
	if request.Parent != nil && request.Parent.PublicKey != nil {
		publicKey, err := clonePublicKey(request.Parent.PublicKey)
		if err != nil {
			return CertificateRequest{}, fmt.Errorf("copy parent public key: %w", err)
		}
		cloned.Parent.PublicKey = publicKey
	}
	if request.SubjectPublicKey != nil {
		publicKey, err := clonePublicKey(request.SubjectPublicKey)
		if err != nil {
			return CertificateRequest{}, fmt.Errorf("copy subject public key: %w", err)
		}
		cloned.SubjectPublicKey = publicKey
	}
	return cloned, nil
}

func clonePublicKey(publicKey crypto.PublicKey) (crypto.PublicKey, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	cloned, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key copy: %w", err)
	}
	return cloned, nil
}

func cloneCertificate(
	certificate *x509.Certificate,
) (*x509.Certificate, error) {
	if certificate == nil {
		return nil, nil
	}
	cloned := *certificate
	cloned.Raw = slices.Clone(certificate.Raw)
	cloned.RawTBSCertificate = slices.Clone(certificate.RawTBSCertificate)
	cloned.RawSubjectPublicKeyInfo = slices.Clone(certificate.RawSubjectPublicKeyInfo)
	cloned.RawSubject = slices.Clone(certificate.RawSubject)
	cloned.RawIssuer = slices.Clone(certificate.RawIssuer)
	cloned.Signature = slices.Clone(certificate.Signature)
	if certificate.SerialNumber != nil {
		cloned.SerialNumber = new(big.Int).Set(certificate.SerialNumber)
	}
	var err error
	cloned.Issuer, err = cloneName(certificate.Issuer)
	if err != nil {
		return nil, fmt.Errorf("copy issuer name: %w", err)
	}
	cloned.Subject, err = cloneName(certificate.Subject)
	if err != nil {
		return nil, fmt.Errorf("copy subject name: %w", err)
	}
	cloned.Extensions = cloneExtensions(certificate.Extensions)
	cloned.ExtraExtensions = cloneExtensions(certificate.ExtraExtensions)
	cloned.UnhandledCriticalExtensions = cloneObjectIdentifiers(
		certificate.UnhandledCriticalExtensions,
	)
	cloned.ExtKeyUsage = slices.Clone(certificate.ExtKeyUsage)
	cloned.UnknownExtKeyUsage = cloneObjectIdentifiers(certificate.UnknownExtKeyUsage)
	cloned.SubjectKeyId = slices.Clone(certificate.SubjectKeyId)
	cloned.AuthorityKeyId = slices.Clone(certificate.AuthorityKeyId)
	cloned.OCSPServer = slices.Clone(certificate.OCSPServer)
	cloned.IssuingCertificateURL = slices.Clone(certificate.IssuingCertificateURL)
	cloned.DNSNames = slices.Clone(certificate.DNSNames)
	cloned.EmailAddresses = slices.Clone(certificate.EmailAddresses)
	cloned.IPAddresses = make([]net.IP, len(certificate.IPAddresses))
	for index, address := range certificate.IPAddresses {
		cloned.IPAddresses[index] = slices.Clone(address)
	}
	cloned.URIs = make([]*url.URL, len(certificate.URIs))
	for index, uri := range certificate.URIs {
		if uri != nil {
			uriCopy := *uri
			cloned.URIs[index] = &uriCopy
		}
	}
	cloned.PermittedDNSDomains = slices.Clone(certificate.PermittedDNSDomains)
	cloned.ExcludedDNSDomains = slices.Clone(certificate.ExcludedDNSDomains)
	cloned.PermittedIPRanges = cloneIPRanges(certificate.PermittedIPRanges)
	cloned.ExcludedIPRanges = cloneIPRanges(certificate.ExcludedIPRanges)
	cloned.PermittedEmailAddresses = slices.Clone(certificate.PermittedEmailAddresses)
	cloned.ExcludedEmailAddresses = slices.Clone(certificate.ExcludedEmailAddresses)
	cloned.PermittedURIDomains = slices.Clone(certificate.PermittedURIDomains)
	cloned.ExcludedURIDomains = slices.Clone(certificate.ExcludedURIDomains)
	cloned.CRLDistributionPoints = slices.Clone(certificate.CRLDistributionPoints)
	cloned.PolicyIdentifiers = cloneObjectIdentifiers(certificate.PolicyIdentifiers)
	cloned.Policies = slices.Clone(certificate.Policies)
	cloned.PolicyMappings = slices.Clone(certificate.PolicyMappings)
	return &cloned, nil
}

func cloneName(name pkix.Name) (pkix.Name, error) {
	name.Country = slices.Clone(name.Country)
	name.Organization = slices.Clone(name.Organization)
	name.OrganizationalUnit = slices.Clone(name.OrganizationalUnit)
	name.Locality = slices.Clone(name.Locality)
	name.Province = slices.Clone(name.Province)
	name.StreetAddress = slices.Clone(name.StreetAddress)
	name.PostalCode = slices.Clone(name.PostalCode)
	var err error
	name.Names, err = cloneAttributeTypeAndValues(name.Names)
	if err != nil {
		return pkix.Name{}, fmt.Errorf("copy parsed attributes: %w", err)
	}
	name.ExtraNames, err = cloneAttributeTypeAndValues(name.ExtraNames)
	if err != nil {
		return pkix.Name{}, fmt.Errorf("copy extra attributes: %w", err)
	}
	return name, nil
}

func cloneAttributeTypeAndValues(
	values []pkix.AttributeTypeAndValue,
) ([]pkix.AttributeTypeAndValue, error) {
	cloned := slices.Clone(values)
	for index := range cloned {
		cloned[index].Type = slices.Clone(cloned[index].Type)
		value, err := cloneAttributeValue(cloned[index].Value)
		if err != nil {
			return nil, fmt.Errorf("attribute %d: %w", index, err)
		}
		cloned[index].Value = value
	}
	return cloned, nil
}

func cloneAttributeValue(value any) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return value, nil
	case asn1.Enumerated:
		return typed, nil
	case asn1.Flag:
		return typed, nil
	case time.Time:
		return typed, nil
	case []byte:
		return slices.Clone(typed), nil
	case asn1.ObjectIdentifier:
		return slices.Clone(typed), nil
	case asn1.BitString:
		typed.Bytes = slices.Clone(typed.Bytes)
		return typed, nil
	case asn1.RawValue:
		typed.Bytes = slices.Clone(typed.Bytes)
		typed.FullBytes = slices.Clone(typed.FullBytes)
		return typed, nil
	case *big.Int:
		if typed == nil {
			return (*big.Int)(nil), nil
		}
		return new(big.Int).Set(typed), nil
	case []string:
		return slices.Clone(typed), nil
	default:
		return nil, fmt.Errorf(
			"unsupported mutable or noncanonical ASN.1 attribute value %T",
			value,
		)
	}
}

func cloneIPRanges(ranges []*net.IPNet) []*net.IPNet {
	cloned := make([]*net.IPNet, len(ranges))
	for index, network := range ranges {
		if network == nil {
			continue
		}
		cloned[index] = &net.IPNet{
			IP:   slices.Clone(network.IP),
			Mask: slices.Clone(network.Mask),
		}
	}
	return cloned
}

func cloneExtensions(extensions []pkix.Extension) []pkix.Extension {
	cloned := slices.Clone(extensions)
	for index := range cloned {
		cloned[index].Id = slices.Clone(cloned[index].Id)
		cloned[index].Value = slices.Clone(cloned[index].Value)
	}
	return cloned
}

func cloneObjectIdentifiers(
	identifiers []asn1.ObjectIdentifier,
) []asn1.ObjectIdentifier {
	cloned := slices.Clone(identifiers)
	for index := range cloned {
		cloned[index] = slices.Clone(cloned[index])
	}
	return cloned
}

func sameKeyMetadata(left KeyMetadata, right KeyMetadata) bool {
	return left.Role == right.Role &&
		left.Purpose == right.Purpose &&
		left.Algorithm == right.Algorithm &&
		left.Handle == right.Handle &&
		bytes.Equal(left.PublicName, right.PublicName) &&
		bytes.Equal(left.PublicKeyDER, right.PublicKeyDER) &&
		left.Template == right.Template &&
		left.CreatedAt.Equal(right.CreatedAt) &&
		left.Generation == right.Generation
}

func verifyCertificateSignature(cert *x509.Certificate, parentPub crypto.PublicKey) error {
	tbs := cert.RawTBSCertificate
	sig := cert.Signature
	switch pub := parentPub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, tbs, sig) {
			return errors.New("ed25519 signature verification failed")
		}
		return nil
	case *ecdsa.PublicKey:
		h := sha256.Sum256(tbs)
		if !ecdsa.VerifyASN1(pub, h[:], sig) {
			return errors.New("ecdsa signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		h := sha256.Sum256(tbs)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	default:
		return fmt.Errorf("unsupported parent public key type %T", parentPub)
	}
}
