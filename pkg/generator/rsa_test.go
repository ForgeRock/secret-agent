package generator

import (
	"regexp"
	"testing"
)

func TestGenerateRSAPrivateKey(t *testing.T) {
	value, err := generateRSAPrivateKey()
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	// check privateKey
	if !regexp.MustCompile(`BEGIN RSA PRIVATE KEY`).Match(value) {
		t.Error("Expected PRIVATE KEY match, found none")
	}
}

func TestGenerateRSAPublicKey(t *testing.T) {
	privateKey, err := generateRSAPrivateKey()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	value, err := getRSAPublicKeyFromPrivateKey(privateKey)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`BEGIN RSA PUBLIC KEY`).Match(value) {
		t.Error("Expected BEGIN RSA PUBLIC KEY match, found none")
	}
}

func TestGetRSAPublicKeySSHFromPrivateKey(t *testing.T) {
	privateKey, err := generateRSAPrivateKey()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	value, err := getRSAPublicKeySSHFromPrivateKey(privateKey)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`ssh-rsa AAAA`).Match(value) {
		t.Error("Expected ssh-rsa AAAA match, found none")
	}
}
