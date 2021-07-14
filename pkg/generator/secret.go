package generator

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/secret"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
)

// Secret randomly generated of specified length
type Secret struct {
	Name   string
	Length int
	Value  []byte
}

// References return names of secrets that should be looked up
func (sec *Secret) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads references from data
func (sec *Secret) LoadReferenceData(data map[string][]byte) error {
	return nil
}

// LoadSecretFromManager populates Secret data from secret manager
func (sec *Secret) LoadSecretFromManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	var err error
	secFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, sec.Name)
	sec.Value, err = sm.LoadSecret(context, secFmt)
	if err != nil {
		return err
	}
	return nil
}

// EnsureSecretManager populates secrets manager from Secret data
func (sec *Secret) EnsureSecretManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	var err error
	secFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, sec.Name)
	err = sm.EnsureSecret(context, secFmt, sec.Value)
	if err != nil {
		return err
	}
	return nil
}

// InSecret return true if the key is one found in the secret
func (sec *Secret) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[sec.Name] == nil || sec.IsEmpty() {
		return false
	}
	if bytes.Compare(sec.Value, secObject.Data[sec.Name]) == 0 {
		return true
	}
	return false

}

// Generate generates data
func (sec *Secret) Generate() error {
	value, err := secret.NewPEMSecret(sec.Length)
	if err != nil {
		return err
	}
	sec.Value = value
	return nil
}

// IsEmpty boolean determines if the struct is empty
func (sec *Secret) IsEmpty() bool {
	if len(sec.Value) == 0 {
		return true
	}
	return false

}

// LoadFromData loads data from kubernetes secret
func (sec *Secret) LoadFromData(secData map[string][]byte) {
	sec.Value = secData[sec.Name]
	return
}

// ToKubernetes "marshals" object to kubernetes object
func (sec *Secret) ToKubernetes(secret *corev1.Secret) {
	// data could be nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[sec.Name] = sec.Value
}

// NewSecret creates new Secret type for reconciliation
func NewSecret(keyConfig *v1alpha1.KeyConfig) *Secret {
	password := &Secret{
		Name:   keyConfig.Name,
		Length: *keyConfig.Spec.Length,
	}
	return password
}
