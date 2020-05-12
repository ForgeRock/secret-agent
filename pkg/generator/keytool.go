package generator

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/ForgeRock/secret-agent/pkg/types"
	"github.com/pkg/errors"
)

const (
	// TODO make these configurable with flags
	dsKeyMgrPath = "/opt/gen/opendj/bin/dskeymgr"
	keytoolPath  = "/usr/local/openjdk-11/bin/keytool"
)

var (
	tempDir          = ""
	keystoreFilePath = ""
)

func init() {
	dir, err := ioutil.TempDir("", "secrets")
	if err != nil {
		panic(err)
	}
	tempDir = dir

	keystoreFilePath = fmt.Sprintf("%s/keystore.p12", tempDir)
}

// GenerateDeploymentKey generates a Certificate Authority, AKA deployment key
func GenerateDeploymentKey(password []byte) ([]byte, error) {
	value := []byte{}
	file, err := ioutil.TempFile(tempDir, "create-deployment-key")
	if err != nil {
		return value, err
	}
	defer os.Remove(file.Name())
	err = file.Close()
	if err != nil {
		return value, err
	}
	cmd := exec.Command(
		dsKeyMgrPath, "create-deployment-key",
		"--outputFile", file.Name(),
		"--deploymentKeyPassword", string(password),
	)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return value, errors.Wrap(err, string(stdoutStderr))
	}
	value, err = ioutil.ReadFile(file.Name())
	if err != nil {
		return value, err
	}
	strValue := strings.TrimSuffix(string(value), "\n")

	return []byte(strValue), nil
}

// GenerateTLSKeyPair generates a TLS key pair
func GenerateTLSKeyPair(storePassword, deploymentKey, deploymentKeyPassword []byte, aliasConfig *types.AliasConfig) ([]byte, error) {
	value := []byte{}
	args := []string{"create-tls-key-pair",
		"--deploymentKey", string(deploymentKey),
		"--deploymentKeyPassword", string(deploymentKeyPassword),
		"--keyStoreFile", keystoreFilePath,
		"--keyStorePassword", string(storePassword), // storepass, not keypass
		"--alias", aliasConfig.Alias,
		"--subjectDn", fmt.Sprintf("CN=%s", aliasConfig.CommonName),
	}
	for _, hostname := range aliasConfig.Sans {
		args = append(args, "--hostname")
		args = append(args, fmt.Sprintf("%s", hostname))
	}
	cmd := exec.Command(dsKeyMgrPath, args...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return value, errors.Wrap(err, string(stdoutStderr))
	}
	value, err = ioutil.ReadFile(keystoreFilePath)
	if err != nil {
		return value, err
	}

	return value, nil
}
