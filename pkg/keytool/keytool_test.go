package keytool

import (
	"testing"

	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGenKeyPair(t *testing.T) {
	node := &secretagentv1alpha1.Node{
		Path: []string{"ds", "ssl-key-pair"},
		// TODO
	}
	_, err := GenerateKeyPair(node)
	if err != nil {
		t.Fatalf("Expected no error, got one: %+v", err)
	}
}
