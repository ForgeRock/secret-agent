package keytool

import (
	"testing"

	"github.com/ForgeRock/secret-agent/pkg/types"
)

func TestGenKeyPair(t *testing.T) {
	node := &types.Node{
		Path: []string{"ds", "ssl-key-pair"},
		// TODO
	}
	_, err := GenerateKeyPair(node)
	if err != nil {
		t.Fatalf("Expected no error, got one: %+v", err)
	}
}
