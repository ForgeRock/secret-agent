package generator

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
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
