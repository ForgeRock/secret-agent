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
	v1aliasConfig            *v1alpha1.KeytoolAliasConfig
	refName                  string
	refDataKeys              []string
	refPrivateData           []byte
	refPublicData            []byte
	refKeyStore              []byte
	srcKeyPass, srcStorePass []byte
	// TODO see #95
	tempDir string
}

// References get list of refences needed for generated a alias
func (k *KeyToolImportKeystore) References() ([]string, []string) {
	var refDataKey string
	k.refName, refDataKey = handleRefPath(k.v1aliasConfig.SourcePath)
	// importing certificate keypairs is handled differently
	if k.v1aliasConfig.IsKeyPair {
		k.refDataKeys = append(k.refDataKeys, fmt.Sprintf("%s.pem", refDataKey))
		k.refDataKeys = append(k.refDataKeys, fmt.Sprintf("%s-private.pem", refDataKey))
		return []string{k.refName, k.refName}, k.refDataKeys
	}
	// any keystore to be imported is expected to use storepass,keypass as keys
	k.refDataKeys = []string{refDataKey, "storepass", "keypass"}
	return []string{k.refName, k.refName, k.refName}, k.refDataKeys

}

// LoadReferenceData loads data from references
func (k *KeyToolImportKeystore) LoadReferenceData(data map[string][]byte) error {
	ok := true
	if k.v1aliasConfig.IsKeyPair {
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
	keyStoreKeyName := fmt.Sprintf("%s/%s", k.refName, k.refDataKeys[0])
	srcKeyPass := fmt.Sprintf("%s/%s", k.refName, "keypass")
	srcStorePass := fmt.Sprintf("%s/%s", k.refName, "storepass")
	k.refKeyStore, ok = data[keyStoreKeyName]
	if !ok {
		return errors.New("no referenced keystore found")
	}
	k.srcKeyPass, ok = data[srcKeyPass]
	if !ok {
		return errors.New("no referenced storepass found")
	}
	k.srcStorePass, ok = data[srcStorePass]
	if !ok {
		return errors.New("no referenced storepass found")
	}
	return nil
}
func (k *KeyToolImportKeystore) importKeyStore(baseCmd cmdRunner) ([]byte, error) {
	// keytool -importkeystore -destalias sms.transport.key -srcalias sms.transport.key -srcstoretype jceks -srckeystore sms-transport-key/sms-transport
	noop := []byte{}
	srcKeyStorePath := filepath.Join(k.tempDir, "srckeystore")
	cmd := "-importkeystore"
	err := ioutil.WriteFile(srcKeyStorePath, k.refKeyStore, 0600)
	if err != nil {
		return noop, err
	}
	importArgs := []string{
		"-srckeystore", srcKeyStorePath,
		"-srcstorepass", string(k.srcStorePass),
		"-srckeypass", string(k.srcKeyPass),
		"-srcalias", k.v1aliasConfig.Name,
		"-destalias", k.v1aliasConfig.Name,
		"-noprompt",
	}
	execCmd := baseCmd(cmd, importArgs)
	return execCmd.CombinedOutput()

}
func (k *KeyToolImportKeystore) importKeyPair(baseCmd cmdRunner) ([]byte, error) {
	publicPath := filepath.Join(k.tempDir, "temp.crt")
	privatePath := filepath.Join(k.tempDir, "temp.key")
	opensslStore := filepath.Join(k.tempDir, "openssl.p12")
	err := ioutil.WriteFile(publicPath, k.refPublicData, 0600)
	if err != nil {
		return []byte{}, err
	}
	err = ioutil.WriteFile(privatePath, k.refPrivateData, 0600)
	if err != nil {
		return []byte{}, err
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
		return []byte{}, errors.Wrap(err, string(output))
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
	return execCmd.CombinedOutput()
}

// Generate creates keytool password alias entry
func (k *KeyToolImportKeystore) Generate(baseCmd cmdRunner) error {
	var err error = nil
	var output []byte
	k.tempDir, err = ioutil.TempDir("", "keystore-*")
	defer os.RemoveAll(k.tempDir)
	if k.v1aliasConfig.IsKeyPair {
		output, err = k.importKeyPair(baseCmd)
	} else {
		output, err = k.importKeyStore(baseCmd)
	}
	if err != nil {
		return errors.Wrap(err, string(output))
	}
	return nil
}
