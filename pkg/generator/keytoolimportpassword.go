package generator

import (
	"io"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

// NewKeyToolImportPassword create a new password alias manager
func NewKeyToolImportPassword(alias *v1alpha1.KeytoolAliasConfig) *KeyToolImportPassword {
	return &KeyToolImportPassword{
		v1aliasConfig: alias,
		refData:       []byte{},
	}
}

// KeyToolImportPassword alias password manager
type KeyToolImportPassword struct {
	v1aliasConfig *v1alpha1.KeytoolAliasConfig
	refName       string
	refDataKey    string
	refData       []byte
}

// References get list of refences needed for generated a alias
func (kp *KeyToolImportPassword) References() ([]string, []string) {
	kp.refName, kp.refDataKey = handleRefPath(kp.v1aliasConfig.SourcePath)
	return []string{kp.refName}, []string{kp.refDataKey}
}

// LoadReferenceData loads data from references
func (kp *KeyToolImportPassword) LoadReferenceData(data map[string][]byte) error {
	if value, ok := data[kp.refDataKey]; ok {
		kp.refData = value
	}
	return nil
}

// Generate creates keytool password alias entry
func (kp *KeyToolImportPassword) Generate(baseCmd cmdRunner) error {
	// echo ${IMP_PASS} | keytool -importpass -alias ${ALIAS} ${KS_PROPS} 2> /dev/null
	// KS_PROPS="-keystore ${KEYSTORE} -storetype ${STORE_TYPE} -storepass ${STORE_PASS} -keypass ${KEY_PASS}"
	cmd := "-importpass"
	args := []string{
		"-alias", kp.v1aliasConfig.Name,
	}
	keyToolCmd := baseCmd(cmd, args)
	keyToolStdIn, err := keyToolCmd.StdinPipe()
	if err != nil {
		return errors.WithMessage(err, "couldn't setup keytool with stdin pipe")
	}
	go func() {
		defer keyToolStdIn.Close()
		io.WriteString(keyToolStdIn, string(kp.refData))
	}()
	output, err := keyToolCmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(output))
	}
	return nil
}
