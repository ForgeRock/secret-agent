package generator

import (
	"bytes"
	"regexp"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestRootCA(t *testing.T) {
	rootCA := NewRootCA()

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
	if !bytes.Equal(testSecret.Data["ca.pem"], rootCA.Cert.CertPEM) {
		t.Error("expected secret data and root ca pem to match")
	}
	if !bytes.Equal(testSecret.Data["ca-private.pem"], rootCA.Cert.PrivateKeyPEM) {
		t.Error("expected seceret data and ca private pem to match")
	}

	// test load data
	testCAPEM := []byte("this is public")
	testCAPrivatePEM := []byte("this is private")
	testSecret.Data["ca.pem"] = testCAPEM
	testSecret.Data["ca-private.pem"] = testCAPrivatePEM
	rootCA.LoadFromData(testSecret.Data)
	if !bytes.Equal(testCAPEM, rootCA.Cert.CertPEM) {
		t.Error("expected secret data and root ca pem to match")
	}
	if !bytes.Equal(testCAPrivatePEM, rootCA.Cert.PrivateKeyPEM) {
		t.Error("expected seceret data and ca private pem to match")
	}

}
