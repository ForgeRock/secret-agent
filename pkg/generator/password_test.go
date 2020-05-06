package generator

import (
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	password, err := GeneratePassword(32)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if len(password) != 32 {
		t.Errorf("Expected length 32, got: %d", len(password))
	}
}
