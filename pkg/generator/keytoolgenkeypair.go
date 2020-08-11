package generator

import (
	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

// KeyToolGenKeyPair alias password manager
type KeyToolGenKeyPair struct {
	v1aliasConfig *v1alpha1.KeytoolAliasConfig
	refName       string
}

// NewKeyToolGenKeyPair create a new password alias manager
func NewKeyToolGenKeyPair(alias *v1alpha1.KeytoolAliasConfig) *KeyToolGenKeyPair {
	return &KeyToolGenKeyPair{
		v1aliasConfig: alias,
	}
}

// References get list of refences needed for generated a alias
func (kp *KeyToolGenKeyPair) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads data from references
func (kp *KeyToolGenKeyPair) LoadReferenceData(data map[string][]byte) error {
	return nil
}

// Generate creates keytool password alias entry
func (kp *KeyToolGenKeyPair) Generate(baseCmd cmdRunner) error {
	//++ keytool -genkeypair -alias rsajwtsigningkey -dname CN=rsajwtsigningkey,O=ForgeRock,L=Bristol,ST=Bristol,C=UK -keyalg RSA -keysize 2048 -sigalg SHA256WITHRSA --validity 3650
	// KS_PROPS="-keystore ${KEYSTORE} -storetype ${STORE_TYPE} -storepass ${STORE_PASS} -keypass ${KEY_PASS}"
	cmd := "-genkeypair"
	args := []string{
		"-alias", kp.v1aliasConfig.Name,
	}
	args = append(args, kp.v1aliasConfig.Args...)
	keyToolCmd := baseCmd(cmd, args)
	output, err := keyToolCmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(output))
	}
	return nil
}
