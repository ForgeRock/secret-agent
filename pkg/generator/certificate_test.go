package generator

import (
	"regexp"
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGeneratePkcs12(t *testing.T) {
	alias := &v1alpha1.AliasConfig{
		Alias:      "asdf",
		Type:       "ca",
		Algorithm:  "ECDSAWithSHA256",
		CommonName: "ForgeRock",
	}
	ca, err := generateCA(alias)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(ca) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
}
