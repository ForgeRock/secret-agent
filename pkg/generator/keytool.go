package generator

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
)

var (
	keytoolPath = flag.String("keytoolPath", "keytool", "The path to the keytool executable")
	opensslPath = flag.String("opensslPath", "openssl", "The path to the openssl executable")
	tempDir     = ""
)

func init() {
	dir, err := ioutil.TempDir("", "secrets")
	if err != nil {
		panic(err)
	}
	tempDir = dir
}

type cmdRunner func(cmdName string, args []string) *exec.Cmd

func baseCommand(execCmd string, baseArgs []string) func(cmdName string, args []string) *exec.Cmd {
	return func(cmdName string, args []string) *exec.Cmd {
		cmdArgs := []string{}
		cmdArgs = append(cmdArgs, cmdName)
		cmdArgs = append(cmdArgs, baseArgs...)
		cmdArgs = append(cmdArgs, args...)
		return exec.Command(execCmd, cmdArgs...)
	}
}

// AliasMgr an interface for managing keytool aliases
type AliasMgr interface {
	References() ([]string, []string)
	LoadReferenceData(data map[string][]byte) error
	Generate(baseCmd cmdRunner) error
}

// NewKeyTool creates new keytool instance
func NewKeyTool(key *v1alpha1.KeyConfig) (*KeyTool, error) {
	tool := &KeyTool{}
	tool.Name = key.Name
	tool.V1Spec = key.Spec
	dir, err := ioutil.TempDir("", "store-*")
	if err != nil {
		return &KeyTool{}, errors.WithMessage(err, "couldn't create a temporary keystore file")
	}
	tool.storePath = path.Join(dir, fmt.Sprintf("keytool.%s", tool.V1Spec.StoreType))
	for _, alias := range key.Spec.KeytoolAliases {
		tool.loadAliasManager(alias)
	}
	return tool, nil
}

// KeyTool an object for managing keytool aliases.
type KeyTool struct {
	Name           string
	V1Spec         *v1alpha1.KeySpec
	storePath      string
	storeBytes     []byte
	aliasMgrs      []AliasMgr
	keyToolCmd     cmdRunner
	storePassValue string
	keyPassValue   string
}

func (kp *KeyTool) baseCommand(execCmd string, baseArgs []string) func(cmdName string, args []string) *exec.Cmd {
	baseArgs = []string{
		"-storetype", string(kp.V1Spec.StoreType),
		"-storepass", kp.keyPassValue,
		"-keypass", kp.storePassValue,
		"-keystore", kp.storePath,
	}
	return func(cmdName string, args []string) *exec.Cmd {
		cmdArgs := []string{}
		cmdArgs = append(cmdArgs, cmdName)
		cmdArgs = append(cmdArgs, baseArgs...)
		cmdArgs = append(cmdArgs, args...)
		return exec.Command(execCmd, cmdArgs...)
	}
}
func (kp *KeyTool) loadAliasManager(alias *v1alpha1.KeytoolAliasConfig) {
	switch alias.Cmd {
	case v1alpha1.KeytoolCmdImportpassword:
		pwdAlias := NewKeyToolImportPassword(alias)
		kp.aliasMgrs = append(kp.aliasMgrs, pwdAlias)
		return
	}
}

// InSecret return true if the key is one found in the secret
func (kp *KeyTool) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[kp.Name] == nil || kp.IsEmpty() {
		return false
	}
	if bytes.Compare(kp.storeBytes, secObject.Data[kp.Name]) == 0 {
		return true
	}
	return false
}

// References all names the ids of references required for generation
func (kp *KeyTool) References() ([]string, []string) {
	refNames := []string{}
	refDataKeys := []string{}
	for _, mgr := range kp.aliasMgrs {
		_refNames, _refDataKeys := mgr.References()
		refNames = append(refNames, _refNames...)
		refDataKeys = append(refDataKeys, _refDataKeys...)
	}
	if kp.V1Spec.StorePassPath != "" {
		storePassName, storePassDataKey := handleRefPath(kp.V1Spec.StorePassPath)
		refNames = append(refNames, storePassName)
		refDataKeys = append(refDataKeys, storePassDataKey)
	}
	if kp.V1Spec.KeyPassPath != "" {
		keyPassName, keyPassDataKey := handleRefPath(kp.V1Spec.KeyPassPath)
		refNames = append(refNames, keyPassName)
		refDataKeys = append(refDataKeys, keyPassDataKey)
	}
	return refNames, refDataKeys
}

// LoadReferenceData load all alias reference data
func (kp *KeyTool) LoadReferenceData(data map[string][]byte) error {
	_, keyPassDataKey := handleRefPath(kp.V1Spec.KeyPassPath)
	_, storePassDataKey := handleRefPath(kp.V1Spec.StorePassPath)
	kp.storePassValue = string(data[storePassDataKey])
	kp.keyPassValue = string(data[keyPassDataKey])
	for _, mgr := range kp.aliasMgrs {
		if err := mgr.LoadReferenceData(data); err != nil {
			return err
		}
	}
	return nil
}

// LoadSecretFromManager load keystore from secrete manager
func (kp *KeyTool) LoadSecretFromManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// EnsureSecretManager adds keystore to secret manager
func (kp *KeyTool) EnsureSecretManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// Generate keystore and all of its aliases
func (kp *KeyTool) Generate() error {
	// clean up after ourselves, we store as bytes in memory
	defer os.RemoveAll(kp.storePath)
	baseArgs := []string{
		"-storetype", string(kp.V1Spec.StoreType),
		"-storepass", kp.storePassValue,
		"-keypass", kp.keyPassValue,
		"-keystore", kp.storePath,
	}
	cmd := baseCommand(*keytoolPath, baseArgs)
	for _, mgr := range kp.aliasMgrs {
		if err := mgr.Generate(cmd); err != nil {
			return err
		}
	}
	storeBytes, err := ioutil.ReadFile(kp.storePath)
	if err != nil {
		return errors.WithStack(err)
	}
	kp.storeBytes = storeBytes
	return nil
}

// LoadFromData keystore from from bytes
func (kp *KeyTool) LoadFromData(secData map[string][]byte) {
	if keyStoreBytes, ok := secData[kp.Name]; ok {
		kp.storeBytes = keyStoreBytes
	}

}

// IsEmpty test if the keystore is empty
func (kp *KeyTool) IsEmpty() bool {
	return len(kp.storeBytes) == 0
}

// ToKubernetes serializes data to kubernetes secret
func (kp *KeyTool) ToKubernetes(secObject *corev1.Secret) {
	if secObject.Data == nil {
		secObject.Data = make(map[string][]byte)
	}
	secObject.Data[kp.Name] = kp.storeBytes
}

///////////////////
// TODO chopping block or maybe relocate
//////////////////
// GetKeystore reads the keystore file and returns it's contents
//   it assumes the file was created during the alias commands
func GetKeystore(nodePath []string) ([]byte, error) {
	keystorePath := getKeystoreFilePath(nodePath)
	contents, err := ioutil.ReadFile(keystorePath)
	defer os.Remove(keystorePath)
	if err != nil {
		return contents, errors.WithStack(err)
	}

	return contents, nil
}

// ImportCertFromPEM adds a PEM encoded cert to a keystore
func ImportCertFromPEM(certPEM, storePassword []byte, aliasConfig *v1alpha1.AliasConfig) error {
	keystorePath := getKeystoreFilePath(aliasConfig.Node.Path)
	certPath := fmt.Sprintf("%s/cert-cert", tempDir)
	err := ioutil.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		return errors.WithStack(err)
	}
	defer os.Remove(certPath)
	// use keytool to import
	args := []string{"-importcert", "-trustcacerts",
		"-alias", aliasConfig.Alias,
		"-file", certPath,
		"-keystore", keystorePath,
		"-keypass", string(storePassword), // storepass, not keypass
		"-storepass", string(storePassword), // storepass, not keypass
		"-noprompt",
	}
	cmd := exec.Command(*keytoolPath, args...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(stdoutStderr))
	}

	return nil
}

// ImportKeyPairFromPEMs converts a PEM encoded cert and key and adds them to a keystore
func ImportKeyPairFromPEMs(certPEM, keyPEM, storePassword []byte, aliasConfig *v1alpha1.AliasConfig) error {
	keystorePath := getKeystoreFilePath(aliasConfig.Node.Path)
	certPath := fmt.Sprintf("%s/keypair-cert", tempDir)
	keyPath := fmt.Sprintf("%s/keypair-key", tempDir)
	pfxPath := fmt.Sprintf("%s/keypair-pfx", tempDir)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)
	defer os.Remove(pfxPath)

	// use openssl to create a pkcs12 file
	err := ioutil.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		return errors.WithStack(err)
	}
	err = ioutil.WriteFile(keyPath, keyPEM, 0644)
	if err != nil {
		return errors.WithStack(err)
	}
	args := []string{"pkcs12",
		"-export",
		"-in", certPath,
		"-inkey", keyPath,
		"-out", pfxPath,
		"-name", aliasConfig.Alias,
		"-passout", "pass:changeit",
	}
	cmd := exec.Command(*opensslPath, args...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(stdoutStderr))
	}

	// use keytool to import
	args = []string{"-importkeystore",
		"-srckeystore", pfxPath,
		"-destkeystore", keystorePath,
		"-srcstoretype", "pkcs12",
		"-deststoretype", "pkcs12",
		"-srcstorepass", "changeit",
		"-deststorepass", string(storePassword), // storepass, not keypass
		"-srcalias", aliasConfig.Alias,
		"-destalias", aliasConfig.Alias,
		"-noprompt",
	}
	cmd = exec.Command(*keytoolPath, args...)
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, string(stdoutStderr))
	}

	return nil
}

func getKeystoreFilePath(nodePath []string) string {
	return fmt.Sprintf("%s/%s-%s.p12", tempDir, nodePath[0], nodePath[1])
}
