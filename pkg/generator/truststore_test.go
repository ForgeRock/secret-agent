package generator

import (
	"encoding/pem"
	"testing"
	"time"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"software.sslmate.com/src/go-pkcs12"
)

// dev notes: next addition to this should refactor to a test table
func TestTrustStore(t *testing.T) {
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
	testSecret := &corev1.Secret{}
	rootCA.ToKubernetes(testSecret)
	key := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeTrustStore,
		Spec: &v1alpha1.KeySpec{
			TruststoreImportPaths: []string{"testConfig/ca"},
		},
	}
	tsMgr := NewTrustStore(key)
	if empty := tsMgr.IsEmpty(); !empty {
		t.Fatalf("expected trust store to not be empty")
	}
	tsMgr.References()
	tsMgr.LoadReferenceData(map[string][]byte{
		"testConfig/ca.pem": testSecret.Data[rootCA.Name+".pem"],
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
	pemKey := &v1alpha1.KeyConfig{
		Name: "myname",
		Type: v1alpha1.KeyConfigTypeTrustStore,
		Spec: &v1alpha1.KeySpec{
			TruststoreImportPaths: []string{"testConfig/ca"},
			PEMFormat:             true,
		},
	}
	pemtsMgr := NewTrustStore(pemKey)
	if empty := pemtsMgr.IsEmpty(); !empty {
		t.Fatalf("expected trust store to not be empty")
	}
	pemtsMgr.References()
	pemtsMgr.LoadReferenceData(map[string][]byte{
		"testConfig/ca.pem": testSecret.Data[rootCA.Name+".pem"],
	})
	pemtsMgr.Generate()
	pemtestSecret := &corev1.Secret{}
	pemtsMgr.ToKubernetes(pemtestSecret)
	value, ok := pemtestSecret.Data["myname"]
	if ok {
		block, _ := pem.Decode(value)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("failed to decode PEM block containing certificate")
		}
	}
}
