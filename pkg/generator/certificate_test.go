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

var (
	testPrivKey []byte = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
	testPubKey []byte = []byte(`-----BEGIN CERTIFICATE-----
MIID9DCCAlygAwIBAgIQflThPVnt7xIVhQ83vrgZ5jANBgkqhkiG9w0BAQsFADAt
MRYwFAYDVQQKEw1Gb3JnZVJvY2suY29tMRMwEQYDVQQDEwpNYXN0ZXIga2V5MB4X
DTcwMDEwMTAwMDAwMFoXDTcwMDEwMjAwMDAwMFowLTEWMBQGA1UEChMNRm9yZ2VS
b2NrLmNvbTETMBEGA1UEAxMKTWFzdGVyIGtleTCCAaIwDQYJKoZIhvcNAQEBBQAD
ggGPADCCAYoCggGBALmhUuqGBxrg8TXDnhD1q90c1IXkovGeKpA4ON0SvtCkYzs3
lK0IlXeaHAz6TO3RMHiS6wjWjRtQCgOr/25wbTKBNvUocyMmR7kfFJsPkk0fdX+J
3sdEdGReKQ5gTjEk7ub3I80aBlEP4vLufxHKzN3ZvtBfPj3NPot6b3UonEdvEUDH
9n8/B0FE/L7CX/bAbExJ8BKMT9DLhGvNEUezHXecSzkIdx5O0q7kmG/6AyRGn+MV
DKQds1WHFHyDry8hgzma8kXIu3NIrI4Xlrt/9JtfRgrBrSjRKGDLJQZii5v58a+o
am5ZPMqJJTLWOnLL9vjcStSk5tGEtnjuDuathi85KsbIbXqPmclHE+kxs9rAns9y
PKYoNzFjaAb03P09H199len/KFfGiL2ukX0QuL9eYdjvK01LfAnoj47MJz1yknpz
pE8JUf07F/VlC4aCz7PHEuvuxggwBDYPPH2ruq/NvVSmP/is3M5H1aRf7fhJ4mNj
AelhIVY0IY0HXQ9P+QIDAQABoxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEB
CwUAA4IBgQB/xeEJvCSPSC2o1VQVEbdM2MZw8WA3DGXj/olr9k8PjYcOwdnPfS7H
d1pnMYzhBYabBOBdTGPoE/cbszg9JmniCfDah396SlAPYelUoqNH9RhsJWJgF7UT
s1Zi5w/PN9qlSrZSW4jbzMu3e1OeM0du3J4XddO6SLTMK+w2+NuhNO9KKyk0R57d
pqmL8ZWlrB2eIDWrzFpxxV65gNnRDacXat4x4g2ZE2qSWfE0+odKiO+6U/Ip08YX
Ld/PsaIulVenYbIaNm2QQjDXU1ZAU/2yus9sUhF/4PuRBoA1JzH2CBi+TMwde0Hx
I8EI8MYk02F99l71N6Mg/16OH8D0lJSx64AbrikubxRps9VGPv7wxiRbiaCGpfhf
ugLN3tEScGc9DSL6r1MjxWMLeXpYafpC8REN/LgUXSl6Q9wubXgzARMR4pf2rELx
N2MP+7QoMJSZ4NifJeImVJjAplwRWTT/2OMp2XN1si6jyAwN7VP0u9sYqRpNhUch
q2+rwR+KjIc=
-----END CERTIFICATE-----`)
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
	rootCA := NewRootCA(rootCAConfig)
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
	pubK8Key, privK8Key := fmt.Sprintf("%s.pem", key.Name), fmt.Sprintf("%s-private.pem", key.Name)
	data[pubK8Key], data[privK8Key] = testPubKey, testPrivKey
	testKeyMgr.LoadFromData(data)
	if !bytes.Equal(testKeyMgr.Cert.PrivateKeyPEM, testPrivKey) {
		t.Errorf("Expected to find match bytes, found %s", string(testKeyMgr.Cert.PrivateKeyPEM))
	}
	if !bytes.Equal(testKeyMgr.Cert.CertPEM, testPubKey) {
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
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	err = testGenKeyMgrNil.Generate()
	if err != nil {
		t.Fatalf("expected no error when duration is not set %s", err)
	}

	// test uid is set when UserId is provided in dn
	uidKey := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeKeyPair,
		Spec: &v1alpha1.KeySpec{
			Duration:   &metav1.Duration{Duration: testDuration},
			Algorithm:  v1alpha1.AlgorithmTypeSHA256WithRSA,
			SelfSigned: true,
			DistinguishedName: &v1alpha1.DistinguishedName{
				UserId: "admin",
			},
		},
	}
	testKeyMgrUid, err := NewCertKeyPair(uidKey)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	err = testKeyMgrUid.Generate()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	names := testKeyMgrUid.Cert.Cert.Subject.Names
	oid := names[0].Type.String()
	if "0.9.2342.19200300.100.1.1" != oid {
		t.Fatalf("Expected 0.9.2342.19200300.100.1.1, got: %s", oid)
	}
	uid := names[0].Value
	if "admin" != uid {
		t.Fatalf("Expected admin, got: %s", uid)
	}
}
