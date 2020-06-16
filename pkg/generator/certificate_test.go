package generator

import (
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGenerateRootCA(t *testing.T) {
	rootCA, err := GenerateRootCA("ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(rootCA.CertPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN EC PRIVATE KEY`).Match(rootCA.PrivateKeyPEM) {
		t.Error("Expected BEGIN EC PRIVATE KEY match, found none")
	}
}

func TestGenerateSignedCert(t *testing.T) {
	rootCA, err := GenerateRootCA("ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	// ECDSAWithSHA256
	cert, err := GenerateSignedCert(rootCA, v1alpha1.ECDSAWithSHA256, "my-common-name", []string{"asdf", "fdsa"})
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(cert.CertPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN EC PRIVATE KEY`).Match(cert.PrivateKeyPEM) {
		t.Error("Expected BEGIN EC PRIVATE KEY match, found none")
	}
	// check root and sans
	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Cert)
	block, _ := pem.Decode(cert.CertPEM)
	if block == nil {
		t.Fatal("Unable to decode cert")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	opts := x509.VerifyOptions{
		DNSName: "asdf",
		Roots:   roots,
	}
	if _, err := parsedCert.Verify(opts); err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	// check common name
	if parsedCert.Subject.CommonName != "my-common-name" {
		t.Errorf("Expected commonName 'my-common-name', got: %s", parsedCert.Subject.CommonName)
	}

	// SHA256WithRSA
	cert, err = GenerateSignedCert(rootCA, v1alpha1.SHA256WithRSA, "my-common-name", []string{"asdf", "fdsa"})
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(cert.CertPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN RSA PRIVATE KEY`).Match(cert.PrivateKeyPEM) {
		t.Error("Expected BEGIN RSA PRIVATE KEY match, found none")
	}
	// check root and sans
	roots = x509.NewCertPool()
	roots.AddCert(rootCA.Cert)
	block, _ = pem.Decode(cert.CertPEM)
	if block == nil {
		t.Fatal("Unable to decode cert")
	}
	parsedCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	opts = x509.VerifyOptions{
		DNSName: "asdf",
		Roots:   roots,
	}
	if _, err := parsedCert.Verify(opts); err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	// check common name
	if parsedCert.Subject.CommonName != "my-common-name" {
		t.Errorf("Expected commonName 'my-common-name', got: %s", parsedCert.Subject.CommonName)
	}
}

func TestGenerateSignedCertPEM(t *testing.T) {
	rootCA, err := GenerateRootCA("ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	_, certPEM, keyPEM, err := GenerateSignedCertPEM(rootCA.CertPEM, rootCA.PrivateKeyPEM, v1alpha1.ECDSAWithSHA256, "my-common-name", []string{"asdf", "fdsa"})
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(certPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN EC PRIVATE KEY`).Match(keyPEM) {
		t.Error("Expected 'BEGIN EC PRIVATE KEY match, found none")
	}
}

func TestGenerateSharedCert(t *testing.T) {
	_, certPEM, keyPEM, err := GenerateSelfSignedCertPEM("foobar", 1)
	// check
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(certPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN RSA PRIVATE KEY`).Match(keyPEM) {
		t.Error("Expected 'BEGIN RSA PRIVATE KEY match, found none")
	}

}

func TestGenerateTrustStore(t *testing.T) {
	_, certPEM, _, err := GenerateSelfSignedCertPEM("foobar", 1)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := GenerateTrustStoreBundle(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*x509.Certificate
	for len(bundle) > 0 {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		parsed = append(parsed, cert)
	}
	lastCert := parsed[len(parsed)-1]
	if lastCert.Subject.CommonName != "foobar" {
		t.Errorf("expected to find cert with common name of 'foobar' but found %+v", lastCert.Subject.CommonName)
	}

}
