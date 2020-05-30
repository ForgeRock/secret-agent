package generator

import (
	"io/ioutil"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

func TestImportCertFromPEM(t *testing.T) {
	var err error
	tempDir, err = ioutil.TempDir("", "secrets")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	rootCA, err := GenerateRootCA("ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	aliasConfig := &v1alpha1.AliasConfig{
		Alias: "fdsa",
		Node: &v1alpha1.Node{
			Path: []string{"asdfSecret", "qwer"},
		},
	}

	err = ImportCertFromPEM(rootCA.CertPEM, []byte("qwerqwerqwerqwerqwer"), aliasConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	// use keytool to check results
	args := []string{"-c", strings.Join([]string{
		*keytoolPath, "-list",
		"-keystore", getKeystoreFilePath(aliasConfig.Node.Path),
		"-storepass", "qwerqwerqwerqwerqwer",
		"-alias", aliasConfig.Alias,
		"-rfc", "|",
		"awk", "'/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/'",
	}, " ")}
	cmd := exec.Command("bash", args...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", errors.Wrap(err, string(stdoutStderr)))
	}

	expected := strings.TrimSpace(string(rootCA.CertPEM))
	re := regexp.MustCompile(`\r`)
	got := strings.TrimSpace(re.ReplaceAllString(string(stdoutStderr), ""))
	if expected != got {
		t.Errorf("Expected: \n%s\n, got: \n%s\n", expected, got)
	}
}

func TestImportKeyPairFromPEMs(t *testing.T) {
	var err error
	tempDir, err = ioutil.TempDir("", "secrets")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	rootCA, err := GenerateRootCA("ForgeRock")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	// ECDSAWithSHA256
	cert, err := GenerateSignedCert(rootCA, v1alpha1.ECDSAWithSHA256, "my-common-name", []string{"asdf", "fdsa"})
	if err != nil {
		t.Errorf("Expected no error, got: %+v", err)
	}

	aliasConfig := &v1alpha1.AliasConfig{
		Alias: "fdsa",
		Node: &v1alpha1.Node{
			Path: []string{"asdfSecret", "qwer"},
		},
	}
	err = ImportKeyPairFromPEMs(cert.CertPEM, cert.PrivateKeyPEM, []byte("fdsafdsafdsafdsa"), aliasConfig)
	if err != nil {
		t.Fatalf("Expected no error, got one: %+v", err)
	}
	// use keytool to check results
	args := []string{"-c", strings.Join([]string{
		*keytoolPath, "-list",
		"-keystore", getKeystoreFilePath(aliasConfig.Node.Path),
		"-storepass", "fdsafdsafdsafdsa",
		"-alias", aliasConfig.Alias,
		"-rfc", "|",
		"awk", "'/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/'",
	}, " ")}
	cmd := exec.Command("bash", args...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", errors.Wrap(err, string(stdoutStderr)))
	}
	expected := strings.TrimSpace(string(cert.CertPEM))
	re := regexp.MustCompile(`\r`)
	got := strings.TrimSpace(re.ReplaceAllString(string(stdoutStderr), ""))
	if expected != got {
		t.Errorf("Expected: \n%s\n, got: \n%s\n", expected, got)
	}

	// SHA256WithRSA
	cert, err = GenerateSignedCert(rootCA, v1alpha1.SHA256WithRSA, "my-common-name", []string{"asdf", "fdsa"})
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}

	aliasConfig = &v1alpha1.AliasConfig{
		Alias: "fdsa",
		Node: &v1alpha1.Node{
			Path: []string{"asdfSecret", "qwer"},
		},
	}
	err = ImportKeyPairFromPEMs(cert.CertPEM, cert.PrivateKeyPEM, []byte("fdsafdsafdsafdsa"), aliasConfig)
	if err != nil {
		t.Fatalf("Expected no error, got one: %+v", err)
	}
	// use keytool to check results
	args = []string{"-c", strings.Join([]string{
		*keytoolPath, "-list",
		"-keystore", getKeystoreFilePath(aliasConfig.Node.Path),
		"-storepass", "fdsafdsafdsafdsa",
		"-alias", aliasConfig.Alias,
		"-rfc", "|",
		"awk", "'/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/'",
	}, " ")}
	cmd = exec.Command("bash", args...)
	stdoutStderr, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", errors.Wrap(err, string(stdoutStderr)))
	}
	expected = strings.TrimSpace(string(cert.CertPEM))
	re = regexp.MustCompile(`\r`)
	got = strings.TrimSpace(re.ReplaceAllString(string(stdoutStderr), ""))
	if expected != got {
		t.Errorf("Expected: \n%s\n, got: \n%s\n", expected, got)
	}
}
