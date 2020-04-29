package generator

import (
	"testing"
)

func TestGenerateRSAPrivateKey(t *testing.T) {
	_, _, err := generateRSAPrivateKey()
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestGenerateRSAPublicKey(t *testing.T) {
	privateKey, _, err := generateRSAPrivateKey()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	_, err = generatePublicKey(privateKey)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestGenerateRSAPublicKeySSh(t *testing.T) {
	privateKey, _, err := generateRSAPrivateKey()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	_, err = generateRSAPublicKeySSH(privateKey)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}
