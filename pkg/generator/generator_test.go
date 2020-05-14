package generator

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"testing"

	"github.com/ForgeRock/secret-agent/pkg/memorystore/test"
	"github.com/ForgeRock/secret-agent/pkg/types"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var outputRigs = flag.Bool("outputRigs", false, "Write YAML file versions of the test rigs")

func TestOutputTestRigs(t *testing.T) {
	flag.Parse()
	_, config1 := memorystore_test.GetExpectedNodesConfiguration1()
	_, config2 := memorystore_test.GetExpectedNodesConfiguration2()
	rigs := []struct {
		config   *types.Configuration
		filePath string
	}{
		{
			config:   config1,
			filePath: "../../testConfiguration1.yaml",
		},
		{
			config:   config2,
			filePath: "../../testConfiguration2.yaml",
		},
	}
	for _, rig := range rigs {
		if *outputRigs {
			file, err := os.Create(rig.filePath)
			if err != nil {
				t.Fatalf("Expected no error, got: %+v", err)
			}
			defer file.Close()
			// remove all nodes since they cause circular references
			for _, secretConfig := range rig.config.Secrets {
				for _, keyConfig := range secretConfig.Keys {
					keyConfig.Node = nil
					for _, aliasConfig := range keyConfig.AliasConfigs {
						aliasConfig.Node = nil
					}
				}
			}
			encoder := yaml.NewEncoder(file)
			err = encoder.Encode(rig.config)
			if err != nil {
				t.Fatalf("Expected no error, got: %+v", err)
			}
		}
	}
}

func TestRecursivelyGenerateIfMissing(t *testing.T) {
	// setup
	nodes, config := memorystore_test.GetExpectedNodesConfiguration1()

	// recurses
	for _, node := range nodes {
		err := RecursivelyGenerateIfMissing(config, node)
		if err != nil {
			t.Fatalf("Expected no error, got: %+v", err)
		}
		for _, parentNode := range node.Parents {
			if len(parentNode.Value) == 0 {
				t.Errorf("Expected parent %v to have a value, but it's empty", parentNode.Path)
			}
		}
	}

	// doesn't generate new aliases if key exists and not using secrets manager
	// nodes, config = memorystore_test.GetExpectedNodesConfiguration1()
	// for _, node := range nodes {
	//     if node.KeyConfig.Type == types.TypeJCEKS && node.AliasConfig == nil {
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

func TestGenerate_PKCS12(t *testing.T) {
	keystoreFilePath = fmt.Sprintf("%s/keystore.p12", tempDir)
	err := ioutil.WriteFile(keystoreFilePath, []byte("asdf"), 0644)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	defer os.Remove(keystoreFilePath)
	keyConfig := &types.KeyConfig{
		Name: "keystore",
		Type: types.TypePKCS12,
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &types.Node{
		Path:         []string{"asdfSecret", "keystore"},
		SecretConfig: secretConfig,
		KeyConfig:    keyConfig,
	}
	err = Generate(node)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestGenerate_Literal(t *testing.T) {
	keyConfig := &types.KeyConfig{
		Name:  "username",
		Type:  types.TypeLiteral,
		Value: "admin",
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &types.Node{
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
	keyConfig := &types.KeyConfig{
		Name:   "keypass",
		Type:   types.TypePassword,
		Length: 16,
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &types.Node{
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
	asdfPrivateKeyKeyConfig := &types.KeyConfig{
		Name: "myPrivateKey",
		Type: types.TypePrivateKey,
	}
	// setup same secret publicKeySSH
	asdfPublicKey1KeyConfig := &types.KeyConfig{
		Name:           "myPublicKey1",
		Type:           types.TypePublicKeySSH,
		PrivateKeyPath: []string{"asdfSecret", "myPrivateKey"},
	}
	asdfSecretConfig := getSecretConfig(asdfPrivateKeyKeyConfig, asdfPublicKey1KeyConfig)
	// setup other secret publicKeySSH
	fdsaPublicKey1KeyConfig := &types.KeyConfig{
		Name:           "myPublicKey1",
		Type:           types.TypePublicKeySSH,
		PrivateKeyPath: []string{"noMatch", "myPrivateKey"},
	}
	fdsaPublicKey2KeyConfig := &types.KeyConfig{
		Name:           "myPublicKey2",
		Type:           types.TypePublicKeySSH,
		PrivateKeyPath: []string{"asdfSecret", "myPrivateKey"},
	}
	fdsaSecretConfig := &types.SecretConfig{
		Name:      "fdsaSecret",
		Namespace: "default",
		Keys: []*types.KeyConfig{
			fdsaPublicKey1KeyConfig,
			fdsaPublicKey2KeyConfig,
		},
	}

	asdfPublicKey1Node := &types.Node{
		Path:         []string{"asdfSecret", "myPublicKey1"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfPublicKey1KeyConfig,
	}
	fdsaPublicKey2Node := &types.Node{
		Path:         []string{"fdsaSecret", "myPublicKey2"},
		SecretConfig: fdsaSecretConfig,
		KeyConfig:    fdsaPublicKey2KeyConfig,
	}
	asdfPrivateKeyNode := &types.Node{
		Path:         []string{"asdfSecret", "myPrivateKey"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfPrivateKeyKeyConfig,
		Children: []*types.Node{
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

func TestGetValueFromParent(t *testing.T) {
	// parent not found
	dsKeystore := &types.Node{
		Path: []string{"ds", "keystore"},
	}
	_, err := getValueFromParent([]string{"ds", "keystore.pin"}, dsKeystore)
	np := &noParentWithPathError{}
	if !errors.As(err, &np) {
		t.Errorf("Expected noParentWithPathError error, got: %T", errors.Cause(err))
	}

	// parent found, but empty
	dsKeystorePin := &types.Node{
		Path: []string{"ds", "keystore.pin"},
	}
	dsKeystore.Parents = []*types.Node{dsKeystorePin}
	_, err = getValueFromParent([]string{"ds", "keystore.pin"}, dsKeystore)
	ev := &emptyValueError{}
	if !errors.As(err, &ev) {
		t.Errorf("Expected emptyValueError error, got: %T", errors.Cause(err))
	}

	// no error
	dsKeystorePin.Value = []byte("asdf")
	_, err = getValueFromParent([]string{"ds", "keystore.pin"}, dsKeystore)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func getSecretConfig(keyConfigs ...*types.KeyConfig) *types.SecretConfig {
	return &types.SecretConfig{
		Name:      "asdfSecret",
		Namespace: "default",
		Keys:      keyConfigs,
	}
}
