package generator

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func TestGenKeyPair(t *testing.T) {
	pwdSpec := &v1alpha1.KeyConfig{
		Name: "testConfig",
		Type: "keytool",
		Spec: &v1alpha1.KeySpec{
			StorePassPath: "storepass/pass",
			StoreType:     "pkcs12",
			KeyPassPath:   "keypass/pass",
			KeytoolAliases: []*v1alpha1.KeytoolAliasConfig{
				{
					Name: "testkp",
					Cmd:  "genkeypair",
					Args: []string{"-keyalg", "RSA", "-keysize", "2048",
						"-sigalg", "SHA256WITHRSA", "-validity", "3650",
						"-dname", "CN=testkp,O=SA,L=Bristol,ST=Bristol,C=UK"},
				},
			},
		},
	}
	keyToolMgr, err := NewKeyTool(pwdSpec)
	if err != nil {
		t.Fatal(err)
	}

	keyToolMgr.References()
	keyToolMgr.LoadReferenceData(map[string][]byte{
		"storepass/pass": []byte("password1"),
		"keypass/pass":   []byte("password2"),
	})
	err = keyToolMgr.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyToolMgr.storeDir); os.IsNotExist(err) {
		os.Mkdir(keyToolMgr.storeDir, 0700)
	}
	baseArgs := []string{
		"-storetype", string(keyToolMgr.V1Spec.StoreType),
		"-storepass", keyToolMgr.storePassValue,
		"-keypass", keyToolMgr.keyPassValue,
		"-keystore", keyToolMgr.storePath,
	}
	baseCmd := execCommand(*keytoolPath, baseArgs)
	args := []string{
		"-alias", "testkp",
	}
	if _, err := os.Stat(keyToolMgr.storePath); !os.IsNotExist(err) {
		t.Error("expected keyToolMgr to cleanup store but didn't")
	}
	ioutil.WriteFile(keyToolMgr.storePath, keyToolMgr.storeBytes, 0600)
	defer os.RemoveAll(keyToolMgr.storeDir)
	cmd := baseCmd("-list", args)
	results, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(string(results))
	}
	if !strings.Contains(string(results), string(pwdSpec.Spec.KeytoolAliases[0].Name)) {
		t.Errorf("Expected Alias %s to exist but found: \n %s", string(pwdSpec.Spec.KeytoolAliases[0].Name), string(results))
	}
}
