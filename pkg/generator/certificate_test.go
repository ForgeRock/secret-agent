package generator

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKeyPair(t *testing.T) {
	// loading references
	rootCAConfig := &v1alpha1.KeyConfig{
		Type: v1alpha1.KeyConfigTypeCA,
		Name: "ca",
		Spec: &v1alpha1.KeySpec{
			Duration: &metav1.Duration{Duration: 100 * 365 * 24 * time.Hour}, //100 yrs
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "foo",
			},
		},
	}
	rootCA, err := NewRootCA(rootCAConfig)
	if err != nil {
		t.Fatal(err)
	}
	rootCA.Generate()
	rootCAData := make(map[string][]byte, 1)
	rootCAData["foo/ca.pem"] = rootCA.Cert.CertPEM
	rootCAData["foo/ca-private.pem"] = rootCA.Cert.PrivateKeyPEM
	testDuration, _ := time.ParseDuration("5y")
	key := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeKeyPair,
		Spec: &v1alpha1.KeySpec{
			Duration:  &metav1.Duration{Duration: testDuration},
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
	key.Spec.SignedWithPath = "foo/ca"
	testKeyMgr, err = NewCertKeyPair(key)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	// k8s keys
	refNames, refKeys := testKeyMgr.References()
	if len(refNames) != 2 || len(refKeys) != 2 {
		t.Errorf("Expected to find exactly two reference names and two keys")
	}
	// name of secret ref name
	if refNames[0] != "foo" {
		t.Errorf("Expected to find reName of foo, found %s", refNames[0])
	}
	if refKeys[1] != "ca-private.pem" {
		t.Errorf("Expected to find reName of ca-private.pem, found %s", refKeys[1])
	}
	if refKeys[0] != "ca.pem" {
		t.Errorf("Expected to find reName of ca.pem, found %s", refKeys[0])
	}

	// data
	data := make(map[string][]byte, 2)
	pub := []byte("afasfsafasf")
	priv := []byte("asfsafsafaslkmlklklj")
	pubK8Key, privK8Key := fmt.Sprintf("%s.pem", key.Name), fmt.Sprintf("%s-private.pem", key.Name)
	data[pubK8Key], data[privK8Key] = pub, priv
	testKeyMgr.LoadFromData(data)
	if !bytes.Equal(testKeyMgr.Cert.PrivateKeyPEM, priv) {
		t.Errorf("Expected to find match bytes, found %s", string(testKeyMgr.Cert.PrivateKeyPEM))
	}
	if !bytes.Equal(testKeyMgr.Cert.CertPEM, pub) {
		t.Errorf("Expected to find match bytes, found %s", string(testKeyMgr.Cert.CertPEM))
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
	testGenKeyMgr.LoadReferenceData(rootCAData)
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

	testExpired, _ := time.ParseDuration("-72h")
	expiredKey := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeKeyPair,
		Spec: &v1alpha1.KeySpec{
			Duration:   &metav1.Duration{Duration: testExpired},
			Algorithm:  v1alpha1.AlgorithmTypeSHA256WithRSA,
			SelfSigned: true,
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "bar",
			},
		},
	}
	testKeyMgrExpired, err := NewCertKeyPair(expiredKey)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	err = testKeyMgrExpired.Generate()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	expectedBefore, _ := time.Parse("2006-Jan-02", "1970-Jan-01")
	expectedAfter, _ := time.Parse("2006-Jan-02", "1970-Jan-02")
	if testKeyMgrExpired.Cert.Cert.NotAfter != expectedAfter {
		t.Fatalf("Expected 1970-Jan-02 as the end date but found %s", testKeyMgrExpired.Cert.Cert.NotBefore.String())
	}
	if testKeyMgrExpired.Cert.Cert.NotBefore != expectedBefore {
		t.Fatalf("Expected 1970-Jan-01 as the start date but found %s", testKeyMgrExpired.Cert.Cert.NotBefore.String())
	}

	// test nil pointer protection on duration
	keyNil := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeKeyPair,
		Spec: &v1alpha1.KeySpec{
			Algorithm: v1alpha1.AlgorithmTypeSHA256WithRSA,
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "bar",
			},
			SelfSigned: true,
		},
	}
	testGenKeyMgrNil, err := NewCertKeyPair(keyNil)
	err = testGenKeyMgrNil.Generate()
	if err != nil {
		t.Fatalf("expected no error when duration is not set %s", err)
	}

}
