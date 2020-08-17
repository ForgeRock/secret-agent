package generator

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

// NewKeyToolImportKeystore created new
func NewKeyToolImportKeystore(alias *v1alpha1.KeytoolAliasConfig) *KeyToolImportKeystore {
	return &KeyToolImportKeystore{
		v1aliasConfig: alias,
	}
}

// KeyToolImportKeystore alias manager
type KeyToolImportKeystore struct {
	v1aliasConfig  *v1alpha1.KeytoolAliasConfig
	refName        string
	refDataKeys    []string
	refPrivateData []byte
	refPublicData  []byte
	// TODO see #95
	tempDir string
}

// References get list of refences needed for generated a alias
func (k *KeyToolImportKeystore) References() ([]string, []string) {
	var refDataKey string
	k.refName, refDataKey = handleRefPath(k.v1aliasConfig.SourcePath)
	k.refDataKeys = append(k.refDataKeys, fmt.Sprintf("%s.pem", refDataKey))
	k.refDataKeys = append(k.refDataKeys, fmt.Sprintf("%s-private.pem", refDataKey))

	return []string{k.refName, k.refName}, k.refDataKeys
}

// LoadReferenceData loads data from references
func (k *KeyToolImportKeystore) LoadReferenceData(data map[string][]byte) error {
	ok := true
	pubName := fmt.Sprintf("%s/%s", k.refName, k.refDataKeys[0])
	privName := fmt.Sprintf("%s/%s", k.refName, k.refDataKeys[1])
	if k.refPublicData, ok = data[pubName]; !ok {
		return errors.Wrap(errNoRefFound, fmt.Sprintf("no data for %s", pubName))
	}
	if k.refPrivateData, ok = data[privName]; !ok {
		return errors.Wrap(errNoRefFound, fmt.Sprintf("no data for %s", privName))
	}
	return nil
}

// Generate creates keytool password alias entry
func (k *KeyToolImportKeystore) Generate(baseCmd cmdRunner) error {
	var err error = nil
	k.tempDir, err = ioutil.TempDir("", "keystore-*")
	defer os.RemoveAll(k.tempDir)
	// write to file
	publicPath := filepath.Join(k.tempDir, "temp.crt")
	privatePath := filepath.Join(k.tempDir, "temp.key")
	opensslStore := filepath.Join(k.tempDir, "openssl.p12")
	err = ioutil.WriteFile(publicPath, k.refPublicData, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(privatePath, k.refPrivateData, 0600)
	if err != nil {
		return err
	}
	opensslArgs := []string{"pkcs12",
		"-export",
		"-in", publicPath,
		"-inkey", privatePath,
		"-out", opensslStore,
		"-name", k.v1aliasConfig.Name,
		"-passout", "pass:changeit",
	}
	opensslCmd := exec.Command(*opensslPath, opensslArgs...)
	output, err := opensslCmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(output))
	}
	cmd := "-importkeystore"
	importArgs := []string{
		"-srckeystore", opensslStore,
		"-srcstoretype", "pkcs12",
		"-srcstorepass", "changeit",
		"-srcalias", k.v1aliasConfig.Name,
		"-destalias", k.v1aliasConfig.Name,
		"-noprompt",
	}
	execCmd := baseCmd(cmd, importArgs)
	output, err = execCmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(output))
	}
	return nil
}
