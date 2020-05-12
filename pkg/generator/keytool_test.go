package generator

import (
	"fmt"
	"os"
	"testing"

	"github.com/ForgeRock/secret-agent/pkg/types"
)

func TestGenerateCA(t *testing.T) {
	deploymentKey, err := GenerateDeploymentKey([]byte("asdffdsafdsaasdf"))
	if err != nil {
		t.Fatalf("Expected no error, got one: %+v", err)
	}
	if len(deploymentKey) == 0 {
		t.Error("Expected non-zero length value")
	}
}

func TestGenerateTLSKeyPair(t *testing.T) {
	keystoreFilePath = fmt.Sprintf("%s/keystore-tls-key-pair.p12", tempDir)
	defer os.Remove(keystoreFilePath)
	aliasConfig := &types.AliasConfig{
		Alias:      "asdf",
		CommonName: "ForgeRock",
		Sans:       []string{"*.ds"},
	}
	password := []byte("asdfasdfasdfasdfasdfasdfasdfasdf")
	deploymentKey, err := GenerateDeploymentKey(password)
	if err != nil {
		t.Fatalf("Expected no error, got one: %+v", err)
	}
	_, err = GenerateTLSKeyPair(password, deploymentKey, password, aliasConfig)
	if err != nil {
		t.Errorf("Expected no error, got one: %+v", err)
	}
}
