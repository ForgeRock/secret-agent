package keytool

import (
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGenKeyPair(t *testing.T) {
	node := &v1alpha1.Node{
		Path: []string{"ds", "ssl-key-pair"},
		// TODO
	}
	_, err := GenerateKeyPair(node)
	if err != nil {
		t.Fatalf("Expected no error, got one: %+v", err)
	}
}
