package generator

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	corev1 "k8s.io/api/core/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	"github.com/pkg/errors"
)

// Password randomly generated of specified length
type Password struct {
	Name   string
	Length int
	Value  []byte
}

// References return names of secrets that should be looked up
func (pwd *Password) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads references from data
func (pwd *Password) LoadReferenceData(data []map[string][]byte) error {
	return nil
}

// LoadSecretFromManager populates Password data from secret manager
func (pwd *Password) LoadSecretFromManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	var err error
	pwdFmt := fmt.Sprintf("%s_%s_%s", namespace, secretName, pwd.Name)
	pwd.Value, err = secretsmanager.LoadSecret(context, config, pwdFmt)
	if err != nil {
		return err
	}
	return nil
}

// EnsureSecretManager populates secrete manager from Password data
func (pwd *Password) EnsureSecretManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	var err error
	pwdFmt := fmt.Sprintf("%s_%s_%s", namespace, secretName, pwd.Name)
	err = secretsmanager.EnsureSecret(context, config, pwdFmt, pwd.Value)
	if err != nil {
		return err
	}
	return nil
}

// InSecret return true if the key is one found in the secret
func (pwd *Password) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[pwd.Name] == nil || pwd.IsEmpty() {
		if secObject.Data[pwd.Name] == nil {
			return false
		}
		return false
	}
	if bytes.Compare(pwd.Value, secObject.Data[pwd.Name]) == 0 {
		return true
	}
	return false

}

// Generate generates data
func (pwd *Password) Generate() error {

	alphanumericBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, pwd.Length)
	for i := range bytes {
		randInt, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumericBytes))))
		if err != nil {
			return errors.WithStack(err)
		}
		bytes[i] = alphanumericBytes[int(randInt.Int64())]
	}
	pwd.Value = bytes
	return nil
}

// IsEmpty boolean determines if the struct is empty
func (pwd *Password) IsEmpty() bool {
	if len(pwd.Value) == 0 {
		return true
	}
	return false

}

// LoadFromData loads data from kubernetes secret
func (pwd *Password) LoadFromData(secData map[string][]byte) {
	pwd.Value = secData[pwd.Name]
	return
}

// ToKubernetes "marshals" object to kubernetes object
func (pwd *Password) ToKubernetes(secret *corev1.Secret) {
	// data could be nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[pwd.Name] = pwd.Value
}

// NewPassword creates new Password type for reconcilation
func NewPassword(keyConfig *v1alpha1.KeyConfig) (*Password, error) {
	password := &Password{
		Name:   keyConfig.Name,
		Length: *keyConfig.Spec.Length,
	}
	return password, nil
}
