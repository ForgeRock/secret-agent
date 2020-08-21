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

var keytoolPath *string
var opensslPath *string

func init() {
	// follow java home if it exists
	javaHome, exists := os.LookupEnv("JAVA_HOME")
	defaultKeytoolPath := "/usr/bin/keytool"
	if exists {
		defaultKeytoolPath = path.Join(javaHome, "bin/keytool")
	}
	keytoolPath = flag.String("keytoolPath", defaultKeytoolPath, "The path to the keytool executable")
	opensslPath = flag.String("opensslPath", "/usr/bin/openssl", "The path to the openssl executable")
}

type cmdRunner func(cmdName string, args []string) *exec.Cmd

// used for openssl and tests
func execCommand(execCmd string, baseArgs []string) func(cmdName string, args []string) *exec.Cmd {
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

func (kt *KeyTool) baseCommand(execCmd string) func(cmdName string, args []string) *exec.Cmd {
	baseArgs := []string{
		"-storetype", string(kt.V1Spec.StoreType),
		"-storepass", kt.storePassValue,
		"-keypass", kt.keyPassValue,
		"-keystore", kt.storePath,
	}
	return func(cmdName string, args []string) *exec.Cmd {
		// for special cmds
		switch cmdName {
		case "-importkeystore":
			baseArgs = []string{
				"-deststoretype", string(kt.V1Spec.StoreType),
				"-deststorepass", kt.keyPassValue,
				"-destkeypass", kt.storePassValue,
				"-destkeystore", kt.storePath,
			}
		}
		cmdArgs := []string{}
		cmdArgs = append(cmdArgs, cmdName)
		cmdArgs = append(cmdArgs, baseArgs...)
		cmdArgs = append(cmdArgs, args...)
		return exec.Command(execCmd, cmdArgs...)
	}
}
func (kt *KeyTool) loadAliasManager(alias *v1alpha1.KeytoolAliasConfig) {
	switch alias.Cmd {
	case v1alpha1.KeytoolCmdImportpassword:
		pwdAlias := NewKeyToolImportPassword(alias)
		kt.aliasMgrs = append(kt.aliasMgrs, pwdAlias)
	case v1alpha1.KeytoolCmdGenseckey:
		genSecAlias := NewKeyToolGenSecKey(alias)
		kt.aliasMgrs = append(kt.aliasMgrs, genSecAlias)
	case v1alpha1.KeytoolCmdGenkeypair:
		kpAlias := NewKeyToolGenKeyPair(alias)
		kt.aliasMgrs = append(kt.aliasMgrs, kpAlias)
	case v1alpha1.KeytoolCmdImportkeystore:
		importKeyStoreAlias := NewKeyToolImportKeystore(alias)
		kt.aliasMgrs = append(kt.aliasMgrs, importKeyStoreAlias)
	case v1alpha1.KeytoolCmdImportcert:
		importCertAlias := NewKeyToolImportCert(alias)
		kt.aliasMgrs = append(kt.aliasMgrs, importCertAlias)
	}
	return
}

// InSecret return true if the key is one found in the secret
func (kt *KeyTool) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[kt.Name] == nil || kt.IsEmpty() {
		return false
	}
	if bytes.Compare(kt.storeBytes, secObject.Data[kt.Name]) == 0 {
		return true
	}
	return false
}

// References all names the ids of references required for generation
func (kt *KeyTool) References() ([]string, []string) {
	refNames := []string{}
	refDataKeys := []string{}
	for _, mgr := range kt.aliasMgrs {
		_refNames, _refDataKeys := mgr.References()
		refNames = append(refNames, _refNames...)
		refDataKeys = append(refDataKeys, _refDataKeys...)
	}
	if kt.V1Spec.StorePassPath != "" {
		storePassName, storePassDataKey := handleRefPath(kt.V1Spec.StorePassPath)
		refNames = append(refNames, storePassName)
		refDataKeys = append(refDataKeys, storePassDataKey)
	}
	if kt.V1Spec.KeyPassPath != "" {
		keyPassName, keyPassDataKey := handleRefPath(kt.V1Spec.KeyPassPath)
		refNames = append(refNames, keyPassName)
		refDataKeys = append(refDataKeys, keyPassDataKey)
	}
	return refNames, refDataKeys
}

// LoadReferenceData load all alias reference data
func (kt *KeyTool) LoadReferenceData(data map[string][]byte) error {
	kt.storePassValue = string(data[kt.V1Spec.StorePassPath])
	kt.keyPassValue = string(data[kt.V1Spec.KeyPassPath])
	for _, mgr := range kt.aliasMgrs {
		if err := mgr.LoadReferenceData(data); err != nil {
			return err
		}
	}
	return nil
}

// LoadSecretFromManager load keystore from secrete manager
func (kt *KeyTool) LoadSecretFromManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// EnsureSecretManager adds keystore to secret manager
func (kt *KeyTool) EnsureSecretManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// Generate keystore and all of its aliases
func (kt *KeyTool) Generate() error {
	// clean up after ourselves, we store as bytes in memory
	defer os.RemoveAll(kt.storePath)
	cmd := kt.baseCommand(*keytoolPath)
	for _, mgr := range kt.aliasMgrs {
		if err := mgr.Generate(cmd); err != nil {
			return err
		}
	}
	storeBytes, err := ioutil.ReadFile(kt.storePath)
	if err != nil {
		return errors.WithStack(err)
	}
	kt.storeBytes = storeBytes
	return nil
}

// LoadFromData keystore from from bytes
func (kt *KeyTool) LoadFromData(secData map[string][]byte) {
	if keyStoreBytes, ok := secData[kt.Name]; ok {
		kt.storeBytes = keyStoreBytes
	}

}

// IsEmpty test if the keystore is empty
func (kt *KeyTool) IsEmpty() bool {
	return len(kt.storeBytes) == 0
}

// ToKubernetes serializes data to kubernetes secret
func (kt *KeyTool) ToKubernetes(secObject *corev1.Secret) {
	if secObject.Data == nil {
		secObject.Data = make(map[string][]byte)
	}
	secObject.Data[kt.Name] = kt.storeBytes
}
