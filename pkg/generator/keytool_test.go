// +build integration

package generator

import (
	"io/ioutil"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

func TestImportCertFromPEM(t *testing.T) {
	var err error
	tempDir, err = ioutil.TempDir("", "secrets")
	if err != nil {
		t.Fatalf("Expected no error, got: %+v", err)
	}
	GenerateRootCA := func() (rootCA *Certificate, err error) {
		rCA := RootCA{
			ValidDuration: 100 * 365 * 24 * time.Hour, //100 yrs
			Cert:          &Certificate{},
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "secret-agent",
			},
		}
		err = rCA.Generate()
		if err != nil {
			return
		}
		rootCA = rCA.Cert
		return
	}
	rootCA, err := GenerateRootCA()
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

	GenerateSignedCert := func(algorithm v1alpha1.AlgorithmType) (leafCert *Certificate, err error) {
		rCA := RootCA{
			ValidDuration: 100 * 365 * 24 * time.Hour, //100 yrs
			Cert:          &Certificate{},
			DistinguishedName: &v1alpha1.DistinguishedName{
				CommonName: "secret-agent",
			},
		}
		certKeyPair := CertKeyPair{
			RootCA: &rCA,
			Cert:   &Certificate{},
			V1Spec: &v1alpha1.KeySpec{
				Sans:              []string{"asdf", "fdsa"},
				Algorithm:         algorithm,
				DistinguishedName: &v1alpha1.DistinguishedName{},
			},
		}
		err = rCA.Generate()
		if err != nil {
			return
		}
		err = certKeyPair.Generate()
		if err != nil {
			return
		}
		leafCert = certKeyPair.Cert
		return
	}

	// ECDSAWithSHA256
	cert, err := GenerateSignedCert(v1alpha1.AlgorithmTypeECDSAWithSHA256)
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
	cert, err = GenerateSignedCert(v1alpha1.AlgorithmTypeSHA256WithRSA)
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
