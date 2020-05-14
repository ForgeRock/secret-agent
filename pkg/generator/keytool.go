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

// GetKeystore reads the keystore file and returns it's contents
//   it assumes the file was created during the alias commands
func GetKeystore() ([]byte, error) {
	return ioutil.ReadFile(keystoreFilePath)
}

// GenerateDeploymentKey generates a Certificate Authority, AKA deployment key
func GenerateDeploymentKey(deploymentKeyPassword []byte) ([]byte, error) {
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
		"--deploymentKeyPassword", string(deploymentKeyPassword),
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
	tlsKeyPairPath := fmt.Sprintf("%s/master-key", tempDir)
	defer os.Remove(tlsKeyPairPath)
	args = []string{"-exportcert",
		"-keystore", keystoreFilePath,
		"-storepass", string(storePassword), // storepass, not keypass
		"-alias", aliasConfig.Alias,
		"-file", tlsKeyPairPath,
		"-rfc",
	}
	cmd = exec.Command(keytoolPath, args...)
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		return value, errors.Wrap(err, string(stdoutStderr))
	}
	value, err = ioutil.ReadFile(tlsKeyPairPath)
	if err != nil {
		return value, err
	}

	return value, nil
}

// GenerateMasterKeyPair generates a TLS key pair
func GenerateMasterKeyPair(storePassword, deploymentKey, deploymentKeyPassword []byte, aliasConfig *types.AliasConfig) ([]byte, error) {
	value := []byte{}
	args := []string{"export-master-key-pair",
		"--deploymentKey", string(deploymentKey),
		"--deploymentKeyPassword", string(deploymentKeyPassword),
		"--keyStoreFile", keystoreFilePath,
		"--keyStorePassword", string(storePassword), // storepass, not keypass
		"--alias", aliasConfig.Alias,
	}
	cmd := exec.Command(dsKeyMgrPath, args...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return value, errors.Wrap(err, string(stdoutStderr))
	}
	masterKeyPairPath := fmt.Sprintf("%s/master-key", tempDir)
	defer os.Remove(masterKeyPairPath)
	args = []string{"-exportcert",
		"-keystore", keystoreFilePath,
		"-storepass", string(storePassword), // storepass, not keypass
		"-alias", aliasConfig.Alias,
		"-file", masterKeyPairPath,
		"-rfc",
	}
	cmd = exec.Command(keytoolPath, args...)
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		return value, errors.Wrap(err, string(stdoutStderr))
	}
	value, err = ioutil.ReadFile(masterKeyPairPath)
	if err != nil {
		return value, err
	}

	return value, nil
}

// GenerateCACert generates a TLS key pair
func GenerateCACert(storePassword, deploymentKey, deploymentKeyPassword []byte, aliasConfig *types.AliasConfig) ([]byte, error) {
	// export from deployment key
	value := []byte{}
	file, err := ioutil.TempFile(tempDir, "create-ca-cert.pem")
	if err != nil {
		return value, err
	}
	defer os.Remove(file.Name())
	err = file.Close()
	args := []string{"export-ca-cert",
		"--outputFile", file.Name(),
		"--deploymentKey", string(deploymentKey),
		"--deploymentKeyPassword", string(deploymentKeyPassword),
	}
	cmd := exec.Command(dsKeyMgrPath, args...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return value, errors.Wrap(err, string(stdoutStderr))
	}

	// import into keystore
	args = []string{"-import",
		"-alias", aliasConfig.Alias,
		"-trustcacerts",
		"-noprompt",
		"-file", file.Name(),
		"-destkeystore", keystoreFilePath,
		"-deststoretype", "pkcs12",
		"-deststorepass", string(storePassword), // storepass, not keypass
		"-destkeypass", string(storePassword), // storepass, not keypass
	}
	cmd = exec.Command(keytoolPath, args...)
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		return value, errors.Wrap(err, string(stdoutStderr))
	}
	value, err = ioutil.ReadFile(file.Name())
	if err != nil {
		return value, err
	}

	return value, nil
}
