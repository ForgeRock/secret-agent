// +build integration

package generator

import (
	"bytes"
	"flag"
	"io/ioutil"
	"os"
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/memorystore"
	"github.com/ForgeRock/secret-agent/pkg/memorystore/testrig"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var outputRigs = flag.Bool("outputRigs", false, "Write YAML file versions of the test rigs")

func TestOutputTestRigs(t *testing.T) {
	flag.Parse()
	if *outputRigs {
		_, config1 := testrig.GetExpectedNodesConfiguration1()
		_, config2 := testrig.GetExpectedNodesConfiguration2()
		rigs := []struct {
			config   *v1alpha1.SecretAgentConfigurationSpec
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
	nodes, config := testrig.GetExpectedNodesConfiguration1()

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
	nodes, config = testrig.GetExpectedNodesConfiguration1()
	for _, node := range nodes {
		if node.KeyConfig.Type == v1alpha1.TypePKCS12 && node.AliasConfig == nil {
			node.Value = []byte("Asdf")
		}
	}
	for _, node := range nodes {
		err := RecursivelyGenerateIfMissing(config, node)
		if err != nil {
			t.Errorf("Expected no error, got: %+v", err)
		}
	}
	for _, node := range nodes {
		if len(node.Path) == 3 { // is an Alias Node
			if len(node.Value) != 0 {
				t.Errorf("Expected node %v to have no Value, but it has \n'%v'", node.Path, string(node.Value))
			}
		}
	}

	// doesn't regenerate if value already exists
	newNodes, _ := testrig.GetExpectedNodesConfiguration1()
	// copy existing values to new nodes
	for _, newNode := range newNodes {
		for _, node := range nodes {
			if memorystore.Equal(node.Path, newNode.Path) {
				newNode.Value = node.Value
			}
			break
		}
	}
	// trigger generate again
	for _, node := range nodes {
		err := RecursivelyGenerateIfMissing(config, node)
		if err != nil {
			t.Errorf("Expected no error, got: %+v", err)
		}
	}
	// compare new to regenerated
	for _, newNode := range newNodes {
		for _, node := range nodes {
			if memorystore.Equal(node.Path, newNode.Path) {
				if bytes.Compare(node.Value, newNode.Value) != 0 {
					t.Errorf("Expected: \n%s\n, got: \n%s\n", string(newNode.Value), string(node.Value))
				}
			}
			break
		}
	}
}

func TestGenerate_PKCS12(t *testing.T) {
	keystorePath := getKeystoreFilePath([]string{"asdfSecret", "keystorePKCS12"})
	err := ioutil.WriteFile(keystorePath, []byte("asdf"), 0644)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	defer os.Remove(keystorePath)
	keyConfig := &v1alpha1.KeyConfig{
		Name: "keystore",
		Type: v1alpha1.TypePKCS12,
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &v1alpha1.Node{
		Path:         []string{"asdfSecret", "keystorePKCS12"},
		SecretConfig: secretConfig,
		KeyConfig:    keyConfig,
	}
	err = Generate(node)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}
}

func TestGenerate_Literal(t *testing.T) {
	keyConfig := &v1alpha1.KeyConfig{
		Name:  "username",
		Type:  v1alpha1.TypeLiteral,
		Value: "admin",
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &v1alpha1.Node{
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
	keyConfig := &v1alpha1.KeyConfig{
		Name:   "keypass",
		Type:   v1alpha1.TypePassword,
		Length: 16,
	}
	secretConfig := getSecretConfig(keyConfig)
	node := &v1alpha1.Node{
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
	asdfPrivateKeyKeyConfig := &v1alpha1.KeyConfig{
		Name: "myPrivateKey",
		Type: v1alpha1.TypePrivateKey,
	}
	// setup same secret publicKeySSH
	asdfPublicKey1KeyConfig := &v1alpha1.KeyConfig{
		Name:           "myPublicKey1",
		Type:           v1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"asdfSecret", "myPrivateKey"},
	}
	asdfSecretConfig := getSecretConfig(asdfPrivateKeyKeyConfig, asdfPublicKey1KeyConfig)
	// setup other secret publicKeySSH
	fdsaPublicKey1KeyConfig := &v1alpha1.KeyConfig{
		Name:           "myPublicKey1",
		Type:           v1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"noMatch", "myPrivateKey"},
	}
	fdsaPublicKey2KeyConfig := &v1alpha1.KeyConfig{
		Name:           "myPublicKey2",
		Type:           v1alpha1.TypePublicKeySSH,
		PrivateKeyPath: []string{"asdfSecret", "myPrivateKey"},
	}
	fdsaSecretConfig := &v1alpha1.SecretConfig{
		Name:      "fdsaSecret",
		Namespace: "default",
		Keys: []*v1alpha1.KeyConfig{
			fdsaPublicKey1KeyConfig,
			fdsaPublicKey2KeyConfig,
		},
	}

	asdfPublicKey1Node := &v1alpha1.Node{
		Path:         []string{"asdfSecret", "myPublicKey1"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfPublicKey1KeyConfig,
	}
	fdsaPublicKey2Node := &v1alpha1.Node{
		Path:         []string{"fdsaSecret", "myPublicKey2"},
		SecretConfig: fdsaSecretConfig,
		KeyConfig:    fdsaPublicKey2KeyConfig,
	}
	asdfPrivateKeyNode := &v1alpha1.Node{
		Path:         []string{"asdfSecret", "myPrivateKey"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfPrivateKeyKeyConfig,
		Children: []*v1alpha1.Node{
			asdfPublicKey1Node,
			fdsaPublicKey2Node,
		},
	}
	asdfPublicKey1Node.Parents = append(asdfPublicKey1Node.Parents, asdfPrivateKeyNode)
	fdsaPublicKey2Node.Parents = append(fdsaPublicKey2Node.Parents, asdfPrivateKeyNode)

	// generate
	nodes := []*v1alpha1.Node{asdfPrivateKeyNode, asdfPublicKey1Node, fdsaPublicKey2Node}
	for _, node := range nodes {
		err := Generate(node)
		if err != nil {
			t.Errorf("Expected no error, got: %+v", err)
		}
	}

	// check values
	for _, node := range nodes {
		if len(node.Value) == 0 {
			t.Error("Expected non-zero value")
		}
	}
}

func TestGenerate_CAPrivateKey(t *testing.T) {
	// setup ca
	asdfCAKeyConfig := &v1alpha1.KeyConfig{
		Name: "ca",
		Type: v1alpha1.TypeCA,
	}
	// setup same secret privateKey
	asdfCAPrivateKeyKeyConfig := &v1alpha1.KeyConfig{
		Name:   "private-key",
		Type:   v1alpha1.TypeCAPrivateKey,
		CAPath: []string{"asdfSecret", "ca"},
	}
	asdfSecretConfig := getSecretConfig(asdfCAPrivateKeyKeyConfig, asdfCAKeyConfig)

	asdfCANode := &v1alpha1.Node{
		Path:         []string{"asdfSecret", "ca"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfCAKeyConfig,
	}
	asdfCAPrivateKeyNode := &v1alpha1.Node{
		Path:         []string{"asdfSecret", "private-key"},
		SecretConfig: asdfSecretConfig,
		KeyConfig:    asdfCAPrivateKeyKeyConfig,
		Parents: []*v1alpha1.Node{
			asdfCANode,
		},
	}
	asdfCANode.Children = append(asdfCANode.Children, asdfCAPrivateKeyNode)

	// generate
	err := Generate(asdfCANode)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

	// check privateKey
	if len(asdfCAPrivateKeyNode.Value) == 0 {
		t.Error("Expected non-zero value")
	}
}

func TestGetValueFromParent(t *testing.T) {
	// parent not found
	dsKeystore := &v1alpha1.Node{
		Path: []string{"ds", "keystore"},
	}
	_, err := getValueFromParent([]string{"ds", "keystore.pin"}, dsKeystore)
	np := &noParentWithPathError{}
	if !errors.As(err, &np) {
		t.Errorf("Expected noParentWithPathError error, got: %T", errors.Cause(err))
	}

	// parent found, but empty
	dsKeystorePin := &v1alpha1.Node{
		Path: []string{"ds", "keystore.pin"},
	}
	dsKeystore.Parents = []*v1alpha1.Node{dsKeystorePin}
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

func getSecretConfig(keyConfigs ...*v1alpha1.KeyConfig) *v1alpha1.SecretConfig {
	return &v1alpha1.SecretConfig{
		Name: "asdfSecret",
		Keys: keyConfigs,
	}
}
