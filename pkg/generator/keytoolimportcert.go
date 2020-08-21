package generator

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

// NewKeyToolImportCert created new
func NewKeyToolImportCert(alias *v1alpha1.KeytoolAliasConfig) *KeyToolImportCert {
	return &KeyToolImportCert{
		v1aliasConfig: alias,
	}
}

// KeyToolImportCert alias manager
type KeyToolImportCert struct {
	v1aliasConfig *v1alpha1.KeytoolAliasConfig
	refName       string
	refDataKey    string
	refPublicData []byte
	// TODO see #95
	tempDir string
}

// References get list of refences needed for generated a alias
func (k *KeyToolImportCert) References() ([]string, []string) {
	var refDataKey string
	k.refName, refDataKey = handleRefPath(k.v1aliasConfig.SourcePath)
	k.refDataKey = fmt.Sprintf("%s.pem", refDataKey)
	return []string{k.refName}, []string{k.refDataKey}
}

// LoadReferenceData loads data from references
func (k *KeyToolImportCert) LoadReferenceData(data map[string][]byte) error {
	ok := true
	pubName := fmt.Sprintf("%s/%s", k.refName, k.refDataKey)
	if k.refPublicData, ok = data[pubName]; !ok {
		return errors.Wrap(errNoRefFound, fmt.Sprintf("no data for %s", pubName))
	}
	return nil
}

// Generate creates keytool certificate with its CA alias entry
func (k *KeyToolImportCert) Generate(baseCmd cmdRunner) error {
	var err error = nil
	k.tempDir, err = ioutil.TempDir("", "keystore-*")
	defer os.RemoveAll(k.tempDir)
	// write to file
	publicPath := filepath.Join(k.tempDir, "temp.crt")
	err = ioutil.WriteFile(publicPath, k.refPublicData, 0600)
	if err != nil {
		return err
	}
	cmd := "-importcert"
	importArgs := []string{
		"-trustcacerts",
		"-file", publicPath,
		"-alias", k.v1aliasConfig.Name,
		"-noprompt",
	}
	execCmd := baseCmd(cmd, importArgs)
	output, err := execCmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(output))
	}
	return nil
}
