package k8ssecrets

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	fake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLoadSecret(t *testing.T) {

	k8sSecret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "asdfSecret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte(`admin`),
		},
	}
	k8sSecret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "notloaded",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"otherkey": []byte(`admin`),
		},
	}
	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	client := fake.NewFakeClientWithScheme(scheme, k8sSecret2)
	// Secret is not present in the client, expect an error
	found, err := LoadSecret(client, k8sSecret1.ObjectMeta.Name, k8sSecret1.ObjectMeta.Namespace)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if len(found.Data) != 0 {
		t.Fatalf("Expected an empty secret: %+v", found)
	}
	client = fake.NewFakeClientWithScheme(scheme, k8sSecret1, k8sSecret2)
	// Secret should load this time
	_, err = LoadSecret(client, k8sSecret1.ObjectMeta.Name, k8sSecret1.ObjectMeta.Namespace)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
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
			"otherkey": []byte(`cGFzc3dvcmQ=`),
		},
	}

	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	client := fake.NewFakeClientWithScheme(scheme, k8sSecret2)
	//k8sSecret1 should be created, k8sSecret2 should be updated
	k8sSecret2.Data = map[string][]byte{"otherkey": []byte(`YWRtaW4=`)}
	k8sSecrets := []*corev1.Secret{k8sSecret1, k8sSecret2}
	if _, err := ApplySecrets(client, k8sSecret1); err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if _, err := ApplySecrets(client, k8sSecret2); err != nil {
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
