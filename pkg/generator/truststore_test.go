package generator

import (
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"software.sslmate.com/src/go-pkcs12"
)

func TestTrustStore(t *testing.T) {
	rootCA, err := makeTestNewRootCA(t)
	if err != nil {
		t.Error(err)
	}
	rootCA.Generate()
	testSecret := &corev1.Secret{}
	rootCA.ToKubernetes(testSecret)
	key := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeTrustStore,
		Spec: &v1alpha1.KeySpec{
			TruststoreImportPaths: []string{"testConfig/ca"},
		},
	}
	tsMgr, err := NewTrustStore(key)
	if err != nil {
		t.Fatal(err)
	}
	if empty := tsMgr.IsEmpty(); !empty {
		t.Fatalf("expected no error found: %s", err)
	}
	tsMgr.References()
	tsMgr.LoadReferenceData(map[string][]byte{
		"testConfig/ca.pem": testSecret.Data[rootCA.publicKeyName],
	})
	tsMgr.Generate()
	parsed, err := pkcs12.DecodeTrustStore(tsMgr.Value, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	lastCert := parsed[len(parsed)-1]
	if lastCert.Subject.CommonName != "foo" {
		t.Errorf("expected to find cert with common name of 'foobar' but found %+v", lastCert.Subject.CommonName)
	}
}
