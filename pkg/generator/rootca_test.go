package generator

import (
	"bytes"
	"regexp"
	"testing"
	"time"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeTestNewRootCA(t *testing.T) (*RootCA, error) {
	kc := &v1alpha1.KeyConfig{
		Name: "testConfig",
		Type: "ca",
		Spec: &v1alpha1.KeySpec{
			Duration: nil,
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "foo",
			},
		},
	}
	kc.Spec.Duration = new(metav1.Duration)
	kc.Spec.Duration.Duration, _ = time.ParseDuration("90d")
	rootCA, err := NewRootCA(kc)
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
		return rootCA, errors.WithStack(err)
	}
	return rootCA, nil
}

func TestRootCA(t *testing.T) {
	rootCA, err := makeTestNewRootCA(t)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	// test IsEmpty when empty
	if empty := rootCA.IsEmpty(); !empty {
		t.Error("Expected rootCA to be empty, found it to be not empty")
	}

	// handle empty secret
	testSecret := &corev1.Secret{}
	rootCA.LoadFromData(testSecret.Data)

	// rootCA should still be empty
	if empty := rootCA.IsEmpty(); !empty {
		t.Error("Expected rootCA to be empty, found it to be not empty after given an empty secret")
	}

	// generate cert
	if err := rootCA.Generate(); err != nil {
		t.Errorf("Expected no error for generate, error found %s", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(rootCA.Cert.CertPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN EC PRIVATE KEY`).Match(rootCA.Cert.PrivateKeyPEM) {
		t.Error("Expected BEGIN EC PRIVATE KEY match, found none")
	}

	// test IsEmpty when not
	if empty := rootCA.IsEmpty(); empty {
		t.Error("Expected rootCA to not be empty, found it to be empty")
	}

	// test to kubernetes
	rootCA.ToKubernetes(testSecret)
	if !bytes.Equal(testSecret.Data[rootCA.publicKeyName], rootCA.Cert.CertPEM) {
		t.Error("expected secret data and root ca pem to match")
	}
	if !bytes.Equal(testSecret.Data[rootCA.privateKeyName], rootCA.Cert.PrivateKeyPEM) {
		t.Error("expected seceret data and ca private pem to match")
	}

	// test load data
	testCAPEM := []byte("this is public")
	testCAPrivatePEM := []byte("this is private")
	testSecret.Data[rootCA.publicKeyName] = testCAPEM
	testSecret.Data[rootCA.privateKeyName] = testCAPrivatePEM
	rootCA.LoadFromData(testSecret.Data)
	if !bytes.Equal(testCAPEM, rootCA.Cert.CertPEM) {
		t.Error("expected secret data and root ca pem to match")
	}
	if !bytes.Equal(testCAPrivatePEM, rootCA.Cert.PrivateKeyPEM) {
		t.Error("expected seceret data and ca private pem to match")
	}

}
