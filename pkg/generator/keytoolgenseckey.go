package generator

import (
	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

// KeyToolGenSecKey alias password manager
type KeyToolGenSecKey struct {
	v1aliasConfig *v1alpha1.KeytoolAliasConfig
}

// NewKeyToolGenSecKey create a new password alias manager
func NewKeyToolGenSecKey(alias *v1alpha1.KeytoolAliasConfig) *KeyToolGenSecKey {
	return &KeyToolGenSecKey{
		v1aliasConfig: alias,
	}
}

// References get list of refences needed for generated a alias
func (kp *KeyToolGenSecKey) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads data from references
func (kp *KeyToolGenSecKey) LoadReferenceData(data map[string][]byte) error {
	return nil
}

// Generate creates keytool password alias entry
func (kp *KeyToolGenSecKey) Generate(baseCmd cmdRunner) error {
	// keytool -genseckey -alias selfservicesigntest -keyalg HmacSHA256 -keysize 256
	// KS_PROPS="-keystore ${KEYSTORE} -storetype ${STORE_TYPE} -storepass ${STORE_PASS} -keypass ${KEY_PASS}"
	cmd := "-genseckey"
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
