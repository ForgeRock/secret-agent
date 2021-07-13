package generator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	"github.com/pkg/errors"
	sshlib "golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
)

// SSH randomly generated of specified length
type SSH struct {
	Name          string
	PrivateKeyRSA *rsa.PrivateKey
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
}

// References return names of secrets that should be looked up
func (ssh *SSH) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads references from data
func (ssh *SSH) LoadReferenceData(data map[string][]byte) error {
	return nil
}

// LoadSecretFromManager populates SSH data from secret manager
func (ssh *SSH) LoadSecretFromManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	var err error
	sshPrivateFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, ssh.Name)
	sshPublicFmt := fmt.Sprintf("%s_%s.pub", secretManagerKeyNamespace, ssh.Name)

	ssh.PrivateKeyPEM, err = sm.LoadSecret(context, sshPrivateFmt)
	if err != nil {
		return err
	}
	ssh.PublicKeyPEM, err = sm.LoadSecret(context, sshPublicFmt)
	if err != nil {
		return err
	}
	return nil
}

// EnsureSecretManager populates secrets manager from SSH data
func (ssh *SSH) EnsureSecretManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	sshPrivateFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, ssh.Name)
	sshPublicFmt := fmt.Sprintf("%s_%s.pub", secretManagerKeyNamespace, ssh.Name)

	if err := sm.EnsureSecret(context, sshPrivateFmt, ssh.PrivateKeyPEM); err != nil {
		return err
	}

	if err := sm.EnsureSecret(context, sshPublicFmt, ssh.PublicKeyPEM); err != nil {
		return err
	}
	return nil
}

// InSecret return true if the key is one found in the secret
func (ssh *SSH) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[ssh.Name] == nil || ssh.IsEmpty() {
		return false
	}
	if bytes.Compare(ssh.PrivateKeyPEM, secObject.Data[ssh.Name]) == 0 &&
		bytes.Compare(ssh.PublicKeyPEM, secObject.Data[fmt.Sprintf("%s.pub", ssh.Name)]) == 0 {
		return true
	}
	return false

}

// Generate generates data
func (ssh *SSH) Generate() error {
	var err error

	ssh.PrivateKeyRSA, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.WithStack(err)
	}
	publicKey, err := sshlib.NewPublicKey(&ssh.PrivateKeyRSA.PublicKey)
	if err != nil {
		return errors.WithStack(err)
	}

	buffer := &bytes.Buffer{}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ssh.PrivateKeyRSA),
	}
	if err := pem.Encode(buffer, block); err != nil {
		return errors.WithStack(err)
	}

	ssh.PrivateKeyPEM = buffer.Bytes()
	ssh.PublicKeyPEM = sshlib.MarshalAuthorizedKey(publicKey)

	return nil

}

// IsEmpty boolean determines if the struct is empty
func (ssh *SSH) IsEmpty() bool {
	if len(ssh.PrivateKeyPEM) == 0 || len(ssh.PublicKeyPEM) == 0 {
		return true
	}
	return false

}

// LoadFromData loads data from kubernetes secret
func (ssh *SSH) LoadFromData(secData map[string][]byte) {
	ssh.PrivateKeyPEM = secData[ssh.Name]
	ssh.PublicKeyPEM = secData[fmt.Sprintf("%s.pub", ssh.Name)]
	return
}

// ToKubernetes "marshals" object to kubernetes object
func (ssh *SSH) ToKubernetes(secret *corev1.Secret) {
	// data could be nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[ssh.Name] = ssh.PrivateKeyPEM
	secret.Data[fmt.Sprintf("%s.pub", ssh.Name)] = ssh.PublicKeyPEM
}

// NewSSH creates new SSH type for reconciliation
func NewSSH(keyConfig *v1alpha1.KeyConfig) *SSH {
	ssh := &SSH{
		Name: keyConfig.Name,
	}
	return ssh
}
