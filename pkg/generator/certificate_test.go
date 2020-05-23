package generator

import (
	"regexp"
	"testing"
)

func TestGeneratePkcs12(t *testing.T) {
	rootCA, err := GenerateRootCA("ECDSAWithSHA256", "ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(rootCA.CAPem) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
}
