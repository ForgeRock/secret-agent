package secret

import (
	"bytes"
	"encoding/pem"
	"regexp"
	"testing"
)

func TestSecret(t *testing.T) {
	value, err := NewPEMSecret(256)
	if err != nil {
		t.Error("Found an error when generating secret, not expected")
	}
	if bytes.Equal(value, make([]byte, 256)) {
		t.Error("Found an array of 0 bytes, expected no 0 bytes")

	}
	if !regexp.MustCompile(`-----BEGIN GENERIC SECRET-----`).Match(value) {
		t.Error("Expected '-----BEGIN GENERIC SECRET-----' match, found none")
	}
	block, _ := pem.Decode(value)
	if block == nil || block.Type != "GENERIC SECRET" {
		t.Error("Failed to decode PEM block containing GENERIC SECRET")
	}
	if len(block.Bytes) != 256 {
		t.Error("Expected exactly 256 bytes")
	}
}
