package k8ssecrets

import (
	"testing"

	"github.com/ForgeRock/secret-agent/pkg/types"
	k8sApiv1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLoadExisting(t *testing.T) {
	secretsConfig := getSecretsConfig()
	node := &types.Node{Path: []string{"asdfSecret", "username"}}
	key := &types.KeyConfig{
		Name:  "username",
		Type:  "literal",
		Value: "admin",
		Node:  node,
	}
	secretsConfig[0].Keys = append(secretsConfig[0].Keys, key)

	k8sSecret1 := &k8sApiv1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "asdfSecret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte(`YWRtaW4=`),
		},
	}
	k8sSecret2 := &k8sApiv1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "notloaded",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"otherkey": []byte(`YWRtaW4=`),
		},
	}

	clientSet := fake.NewSimpleClientset(k8sSecret1, k8sSecret2)
	// loads when unset in Node
	err := LoadExisting(clientSet, secretsConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != "admin" {
		t.Errorf("Expected 'admin', got: '%+v'", string(node.Value))
	}
	// does not load when set in Node
	node.Value = []byte("existingAdmin")
	err = LoadExisting(clientSet, secretsConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != "existingAdmin" {
		t.Errorf("Expected 'existingAdmin', got: '%+v'", string(node.Value))
	}
}

func TestApplySecrets(t *testing.T) {
	secretsConfig := getSecretsConfig()
	node := &types.Node{
		Path:  []string{"asdfSecret", "username"},
		Value: []byte("admin"),
	}
	key := &types.KeyConfig{
		Name: "username",
		Node: node,
	}
	secretsConfig[0].Keys = append(secretsConfig[0].Keys, key)

	clientSet := fake.NewSimpleClientset()
	err := ApplySecrets(clientSet, secretsConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	k8sSecret, err := clientSet.CoreV1().Secrets("default").
		Get("asdfSecret", meta_v1.GetOptions{})
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			t.Fatalf("Expected no error, got IsNotFound: %+v", err)
		}
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if k8sSecret.ObjectMeta.Name != "asdfSecret" {
		t.Errorf("Expected asdfSecret, got: %s", k8sSecret.ObjectMeta.Name)
	}
	if string(k8sSecret.Data["username"]) != "YWRtaW4=" {
		t.Errorf("Expected 'YWRtaW4=', got: '%s'", string(k8sSecret.Data["username"]))
	}
	if len(k8sSecret.Data) != 1 {
		t.Errorf("Expected 1 key, got: %d", len(k8sSecret.Data))
	}
}

func getSecretsConfig() []*types.SecretConfig {
	return []*types.SecretConfig{
		&types.SecretConfig{
			Name:      "asdfSecret",
			Namespace: "default",
			Keys:      []*types.KeyConfig{},
		},
	}
}
