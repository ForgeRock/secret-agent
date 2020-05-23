package generator

import (
	"regexp"
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGenerateRootCA(t *testing.T) {
	rootCA, err := GenerateRootCA(v1alpha1.ECDSAWithSHA256, "ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(rootCA.CAPem) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN EC PRIVATE KEY`).Match(rootCA.CAPrivateKeyPEM) {
		t.Error("Expected BEGIN EC PRIVATE KEY match, found none")
	}
}

func TestGetECPublicKeyFromPrivateKey(t *testing.T) {
	rootCA, err := GenerateRootCA(v1alpha1.ECDSAWithSHA256, "ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	publicKeyPEM, err := GetECPublicKeyFromPrivateKey(rootCA.CAPrivateKeyPEM)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`BEGIN EC PUBLIC KEY`).Match(publicKeyPEM) {
		t.Error("Expected BEGIN EC PUBLIC KEY match, found none")
	}
}
