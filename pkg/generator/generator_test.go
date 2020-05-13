package generator

import (
	"regexp"
	"testing"

	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"
	memorystore_test "github.com/ForgeRock/secret-agent/pkg/memorystore/test"
)

func TestRecursivelyGenerateIfMissing(t *testing.T) {
	// setup
	nodes, config := memorystore_test.GetExpectedNodesConfiguration1()

	// recurses
	for _, node := range nodes {
		err := RecursivelyGenerateIfMissing(config, node)
		if err != nil {
			t.Errorf("Expected no error, got: %+v", err)
		}
		for _, parentNode := range node.Parents {
			if len(parentNode.Value) == 0 {
				t.Errorf("Expected parent %v to have a value, but it's empty", parentNode.Path)
			}
		}
	}

	// doesn't generate new aliases if key existing and not using secrets manager
	// nodes, config = memorystore_test.GetExpectedNodesConfiguration1()
	// for _, node := range nodes {
	//     if node.KeyConfig.Type == secretagentv1alpha1.TypeJCEKS {
	//         node.Value = []byte("Asdf")
	//     }
	// }
	// for _, node := range nodes {
	//     err := RecursivelyGenerateIfMissing(config, node)
	//     if err != nil {
	//         t.Errorf("Expected no error, got: %+v", err)
	//     }
	// }
	// for _, node := range nodes {
	//     if len(node.Path) == 3 { // is an Alias Node
	//         if len(node.Value) != 0 {
	//             t.Errorf("Expected node %v to have no Value, but it has \n'%v'", node.Path, string(node.Value))
	//         }
	//     }
	// }

	// doesn't generate if value already exists
}

func TestGenerate_Literal(t *testing.T) {
	keyConfig := &secretagentv1alpha1.KeyConfig{
		Name:  "username",
		Type:  secretagentv1alpha1.TypeLiteral,
		Value: "admin",
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &secretagentv1alpha1.Node{
		Path:         []string{"asdfSecret", "username"},
		SecretConfig: secretConfig,
		KeyConfig:    keyConfig,
	}
	err := Generate(node)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != "admin" {
		t.Errorf("Expected 'admin', got: %s", string(node.Value))
	}
}

func TestGenerate_Password(t *testing.T) {
	keyConfig := &secretagentv1alpha1.KeyConfig{
		Name:   "keypass",
		Type:   secretagentv1alpha1.TypePassword,
		Length: 16,
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &secretagentv1alpha1.Node{
		Path:         []string{"asdfSecret", "keypass"},
		SecretConfig: secretConfig,
		KeyConfig:    keyConfig,
	}
	err := Generate(node)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
	length := len(string(node.Value))
	if length != 16 {
		t.Errorf("Expected length 16, got: %d", length)
	}
}

func TestGenerate_PrivateKey(t *testing.T) {
	// setup privateKey
	asdfPrivateKeyKeyConfig := &secretagentv1alpha1.KeyConfig{
		Name: "myPrivateKey",
		Type: secretagentv1alpha1.TypePrivateKey,
	}
	// setup same secret publicKeySSH
	asdfPublicKey1KeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "myPublicKey1",
		Type:           secretagentv1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"asdfSecret", "myPrivateKey"},
	}
	asdfSecretConfig := getSecretConfig(asdfPrivateKeyKeyConfig, asdfPublicKey1KeyConfig)
	// setup other secret publicKeySSH
	fdsaPublicKey1KeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "myPublicKey1",
		Type:           secretagentv1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"noMatch", "myPrivateKey"},
	}
	fdsaPublicKey2KeyConfig := &secretagentv1alpha1.KeyConfig{
		Name:           "myPublicKey2",
		Type:           secretagentv1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"asdfSecret", "myPrivateKey"},
	}
	fdsaSecretConfig := &secretagentv1alpha1.SecretConfig{
		Name:      "fdsaSecret",
		Namespace: "default",
		Keys: []*secretagentv1alpha1.KeyConfig{
			fdsaPublicKey1KeyConfig,
			fdsaPublicKey2KeyConfig,
		},
	}

	asdfPublicKey1Node := &secretagentv1alpha1.Node{
		Path:         []string{"asdfSecret", "myPublicKey1"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfPublicKey1KeyConfig,
	}
	fdsaPublicKey2Node := &secretagentv1alpha1.Node{
		Path:         []string{"fdsaSecret", "myPublicKey2"},
		SecretConfig: fdsaSecretConfig,
		KeyConfig:    fdsaPublicKey2KeyConfig,
	}
	asdfPrivateKeyNode := &secretagentv1alpha1.Node{
		Path:         []string{"asdfSecret", "myPrivateKey"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfPrivateKeyKeyConfig,
		Children: []*secretagentv1alpha1.Node{
			asdfPublicKey1Node,
			fdsaPublicKey2Node,
		},
	}

	// generate
	err := Generate(asdfPrivateKeyNode)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

	// check privateKey
	if !regexp.MustCompile(`BEGIN RSA PRIVATE KEY`).Match(asdfPrivateKeyNode.Value) {
		t.Error("Expected PRIVATE KEY match, found none")
	}

	// check all publicKeySSH's
	//   asdfSecret_default.myPublicKey1 is set
	if !regexp.MustCompile(`ssh-rsa AAAA`).Match(asdfPublicKey1Node.Value) {
		t.Error("Expected ssh-rsa AAAA match, found none")
	}

	//   fdsaSecret_default.myPublicKey2 is set
	if !regexp.MustCompile(`ssh-rsa AAAA`).Match(fdsaPublicKey2Node.Value) {
		t.Error("Expected ssh-rsa AAAA match, found none")
	}

	//   ensure there's only 2
	if len(asdfPrivateKeyNode.Children) != 2 {
		t.Errorf("Expected 2, got: %d", len(asdfPrivateKeyNode.Children))
	}
}

func getSecretConfig(keyConfigs ...*secretagentv1alpha1.KeyConfig) *secretagentv1alpha1.SecretConfig {
	return &secretagentv1alpha1.SecretConfig{
		Name:      "asdfSecret",
		Namespace: "default",
		Keys:      keyConfigs,
	}
}
