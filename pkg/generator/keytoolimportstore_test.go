package generator

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestImportKeyStore(t *testing.T) {
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
	err := rootCA.Generate()
	if err != nil {
		t.Fatal(err)
	}

	importSpec := &v1alpha1.KeyConfig{
		Name: "testConfig",
		Type: "keytool",
		Spec: &v1alpha1.KeySpec{
			StorePassPath: "storepass/pass",
			StoreType:     "pkcs12",
			KeyPassPath:   "keypass/pass",
			KeytoolAliases: []*v1alpha1.KeytoolAliasConfig{
				{
					Name:       "testimportkeystore",
					Cmd:        "importkeystore",
					SourcePath: "testConfig/ca",
					IsKeyPair:  true,
				},
			},
		},
	}
	keyToolMgr, err := NewKeyTool(importSpec)
	if err != nil {
		t.Fatal(err)
	}

	refNames, refKeys := keyToolMgr.References()
	if len(refNames) != 4 {
		t.Errorf("expected exactly two secrets")

	}
	if len(refKeys) != 4 {
		t.Errorf("expected exactly two secrets")

	}
	// setup rootca data
	rootCAData := make(map[string][]byte, 2)
	rootCAData["testConfig/ca.pem"] = rootCA.Cert.CertPEM
	rootCAData["testConfig/ca-private.pem"] = rootCA.Cert.PrivateKeyPEM
	rootCAData["keypass/pass"] = []byte("myvalue")
	rootCAData["storepass/pass"] = []byte("myvalue")

	keyToolMgr.LoadReferenceData(rootCAData)

	err = keyToolMgr.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyToolMgr.storeDir); os.IsNotExist(err) {
		os.Mkdir(keyToolMgr.storeDir, 0700)
	}
	// check temp doesn't exist
	baseArgs := []string{
		"-storetype", string(keyToolMgr.V1Spec.StoreType),
		"-storepass", keyToolMgr.storePassValue,
		"-keypass", keyToolMgr.keyPassValue,
		"-keystore", keyToolMgr.storePath,
	}
	baseCmd := execCommand(*keytoolPath, baseArgs)
	args := []string{
		"-alias", "testimportkeystore",
	}
	if _, err := os.Stat(keyToolMgr.storePath); !os.IsNotExist(err) {
		t.Error("expected keyToolMgr to cleanup store but didn't")
	}
	// TODO this for some reason wont cast down to it's concrete type
	// keyStoreImport := keyToolMgr.aliasMgrs[0]
	// if _, err := os.Stat(keyStoreImport.(KeyToolImportKeystore).tempDir); !os.IsNotExist(err) {
	// 	t.Error("expected keyToolMgr to cleanup store but didn't")
	// }
	ioutil.WriteFile(keyToolMgr.storePath, keyToolMgr.storeBytes, 0600)
	defer os.RemoveAll(keyToolMgr.storeDir)
	cmd := baseCmd("-list", args)
	results, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(results))
	}
	if !strings.Contains(string(results), string(importSpec.Spec.KeytoolAliases[0].Name)) {
		t.Errorf("Expected Alias %s to exist but found: \n %s", string(keyToolMgr.Name), string(results))
	}
}
