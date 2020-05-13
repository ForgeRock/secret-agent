package k8ssecrets

import (
	"context"
	"testing"

	secretagentv1alpha1 "github.com/ForgeRock/secret-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	fake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLoadExisting(t *testing.T) {
	secretsConfig := getSecretsConfig()
	node := &secretagentv1alpha1.Node{Path: []string{"asdfSecret", "username"}}
	key := &secretagentv1alpha1.KeyConfig{
		Name:  "username",
		Type:  "literal",
		Value: "admin",
		Node:  node,
	}
	secretsConfig[0].Keys = append(secretsConfig[0].Keys, key)

	k8sSecret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "asdfSecret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte(`YWRtaW4=`),
		},
	}
	k8sSecret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "notloaded",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"otherkey": []byte(`YWRtaW4=`),
		},
	}

	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	client := fake.NewFakeClientWithScheme(scheme, k8sSecret1, k8sSecret2)
	// loads when unset in Node
	err := LoadExisting(client, secretsConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != "admin" {
		t.Errorf("Expected 'admin', got: '%+v'", string(node.Value))
	}
	// does not load when set in Node
	node.Value = []byte("existingAdmin")
	err = LoadExisting(client, secretsConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if string(node.Value) != "existingAdmin" {
		t.Errorf("Expected 'existingAdmin', got: '%+v'", string(node.Value))
	}
}

func TestGenerateSecretAPIObjects(t *testing.T) {
	// func GenerateSecretAPIObjects(secretsConfig []*secretagentv1alpha1.SecretConfig) []*corev1.Secret
	secretsConfig := getSecretsConfig()
	node := &secretagentv1alpha1.Node{
		Path:  []string{"asdfSecret", "username"},
		Value: []byte("admin"),
	}
	key := &secretagentv1alpha1.KeyConfig{
		Name: "username",
		Node: node,
	}
	secretsConfig[0].Keys = append(secretsConfig[0].Keys, key)

	k8sSecrets := GenerateSecretAPIObjects(secretsConfig)
	for _, k8sSecret := range k8sSecrets {
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

}

func TestApplySecrets(t *testing.T) {

	k8sSecret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "asdfSecret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte(`YWRtaW4=`),
		},
	}
	k8sSecret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "notloaded",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"otherkey": []byte(`YWRtaW4=`),
		},
	}

	k8sSecrets := []*corev1.Secret{k8sSecret1, k8sSecret2}

	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	client := fake.NewFakeClientWithScheme(scheme)
	err := ApplySecrets(client, k8sSecrets)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	for _, writtenSecret := range k8sSecrets {
		k8sSecret := &corev1.Secret{}
		if err := client.Get(context.TODO(), types.NamespacedName{Name: writtenSecret.Name, Namespace: writtenSecret.Namespace}, k8sSecret); err != nil {
			if k8sErrors.IsNotFound(err) {
				t.Fatalf("Expected no error, got IsNotFound: %+v", err)
			}
			t.Fatalf("Expected no error, got: %+v", err)
		}
		if k8sSecret.ObjectMeta.Name != writtenSecret.ObjectMeta.Name {
			t.Errorf("Expected asdfSecret, got: %s", k8sSecret.ObjectMeta.Name)
		}
		if string(k8sSecret.Data["username"]) != string(writtenSecret.Data["username"]) {
			t.Errorf("Expected 'YWRtaW4=', got: '%s'", string(k8sSecret.Data["username"]))
		}
		if len(k8sSecret.Data) != len(writtenSecret.Data) {
			t.Errorf("Expected 1 key, got: %d", len(k8sSecret.Data))
		}
	}
}

func getSecretsConfig() []*secretagentv1alpha1.SecretConfig {
	return []*secretagentv1alpha1.SecretConfig{
		{
			Name:      "asdfSecret",
			Namespace: "default",
			Keys:      []*secretagentv1alpha1.KeyConfig{},
		},
	}
}
