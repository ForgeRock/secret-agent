package generator

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func TestKeyPair(t *testing.T) {
	loadKeyRefs := func(testKeyMgr KeyMgr) error {
		// loading references
		rootCA := RootCA{
			Cert: &Certificate{},
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "foo",
			},
		}
		rootCA.Generate()
		rootCAData := make(map[string][]byte, 1)
		rootCAData["foo/ca.pem"] = rootCA.Cert.CertPEM
		rootCAData["foo/ca-private.pem"] = rootCA.Cert.PrivateKeyPEM

		return testKeyMgr.LoadReferenceData(rootCAData)
	}
	key := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeKeyPair,
		Spec: &v1alpha1.KeySpec{
			Algorithm: v1alpha1.AlgorithmTypeSHA256WithRSA,
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "bar",
			},
		},
	}
	testKeyMgr, err := NewCertKeyPair(key)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	// test empty
	if isEmpty := testKeyMgr.IsEmpty(); !isEmpty {
		t.Error("Expected keypair to be empty")
	}
	// no signed path
	if testKeyMgr.refName != "" {
		t.Fatalf("refName to be empty but found: %s", testKeyMgr.refName)
	}

	// with path
	key.Spec.SignedWithPath = "foo/bar"
	testKeyMgr, err = NewCertKeyPair(key)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	// k8s keys
	pubK8Key, privK8Key := fmt.Sprintf("%s.pem", key.Name), fmt.Sprintf("%s-private.pem", key.Name)

	// data
	data := make(map[string][]byte, 2)
	pub := []byte("afasfsafasf")
	priv := []byte("asfsafsafaslkmlklklj")
	data[pubK8Key], data[privK8Key] = pub, priv
	testKeyMgr.LoadFromData(data)
	if !bytes.Equal(testKeyMgr.Cert.PrivateKeyPEM, priv) {
		t.Errorf("Expected to find match bytes, found %s", string(testKeyMgr.Cert.PrivateKeyPEM))
	}
	if !bytes.Equal(testKeyMgr.Cert.CertPEM, pub) {
		t.Errorf("Expected to find match bytes, found %s", string(testKeyMgr.Cert.CertPEM))
	}

	// ref names
	refNames, refKeys := testKeyMgr.References()
	if len(refNames) != 1 || len(refKeys) != 1 {
		t.Errorf("Expected to find exactly one referenc")
	}
	if refNames[0] != "foo" {
		t.Errorf("Expected to find reName of foo, found %s", refNames[0])
	}
	if refKeys[0] != "bar" {
		t.Errorf("Expected to find reName of bar, found %s", refKeys[0])
	}
	// // loading references
	// rootCA := NewRootCA()
	// rootCA.Generate()
	// rootCAData := make([]map[string][]byte, 1)
	// rootCAData[0] = make(map[string][]byte, 2)
	// rootCAData[0]["ca.pem"] = rootCA.Cert.CertPEM
	// rootCAData[0]["ca-private.pem"] = rootCA.Cert.PrivateKeyPEM
	// err = testKeyMgr.LoadReferenceData(rootCAData)
	if err := loadKeyRefs(testKeyMgr); err != nil {
		t.Errorf("Expected no error %s", err)
	}
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(testKeyMgr.RootCA.Cert.CertPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN EC PRIVATE KEY`).Match(testKeyMgr.RootCA.Cert.PrivateKeyPEM) {
		t.Error("Expected BEGIN EC PRIVATE KEY match, found none")
	}
	testKeyMgr.Cert.PrivateKeyPEM = []byte("foo bar")
	testKeyMgr.Cert.CertPEM = []byte("foo bar")
	if isEmpty := testKeyMgr.IsEmpty(); isEmpty {
		t.Error("Expected keypair to not be empty")
	}
	testGenKeyMgr, err := NewCertKeyPair(key)
	if err != nil {
		t.Fatalf("Expected no error got: %v", err)
	}
	if testGenKeyMgr == nil {
		t.Errorf("tf")
	}
	loadKeyRefs(testGenKeyMgr)
	if err := testGenKeyMgr.Generate(); err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	if !regexp.MustCompile(`-----BEGIN CERTIFICATE-----`).Match(testGenKeyMgr.Cert.CertPEM) {
		t.Error("Expected '-----BEGIN CERTIFICATE-----' match, found none")
	}
	if !regexp.MustCompile(`BEGIN RSA PRIVATE KEY`).Match(testGenKeyMgr.Cert.PrivateKeyPEM) {
		t.Error("Expected BEGIN RSA PRIVATE KEY match, found none")
	}

	testSecret := &corev1.Secret{}
	testGenKeyMgr.ToKubernetes(testSecret)
	if !bytes.Equal(testSecret.Data[pubK8Key], testGenKeyMgr.Cert.CertPEM) {
		t.Error("expected secret data and root ca pem to match")
	}
	if !bytes.Equal(testSecret.Data[privK8Key], testGenKeyMgr.Cert.PrivateKeyPEM) {
		t.Error("expected seceret data and ca private pem to match")
	}
}
