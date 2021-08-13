package generator

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	secretkey "github.com/ForgeRock/secret-agent/pkg/secret"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
)

// SecretKey randomly generated of specified length
type SecretKey struct {
	Name   string
	Value  []byte
	V1Spec *v1alpha1.KeySpec
}

// References return names of secrets that should be looked up
func (sec *SecretKey) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads references from data
func (sec *SecretKey) LoadReferenceData(data map[string][]byte) error {
	return nil
}

// LoadSecretFromManager populates Secret data from secret manager
func (sec *SecretKey) LoadSecretFromManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	var err error
	secFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, sec.Name)
	sec.Value, err = sm.LoadSecret(context, secFmt)
	if err != nil {
		return err
	}
	return nil
}

// EnsureSecretManager populates secrets manager from Secret data
func (sec *SecretKey) EnsureSecretManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	var err error
	secFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, sec.Name)
	err = sm.EnsureSecret(context, secFmt, sec.Value)
	if err != nil {
		return err
	}
	return nil
}

// InSecret return true if the key is one found in the secret
func (sec *SecretKey) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[sec.Name] == nil || sec.IsEmpty() {
		return false
	}
	if bytes.Compare(sec.Value, secObject.Data[sec.Name]) == 0 {
		return true
	}
	return false

}

// Generate generates data
func (sec *SecretKey) Generate() error {
	var err error
	value := make([]byte, 0)
	switch sec.V1Spec.Algorithm {
	case v1alpha.AlgorithmReadableBits:
		secretkey.NewSecretBits(*sec.V1Spec.Length, false)
	case v1alpha.AlgorithmBinaryBits:
		secretkey.NewSecretBits(*sec.V1Spec.Length, true)
	case v1alpha.AlgorithmGenericPEM:
		secretkey.NewGenericPEMKey(*sec.V1Spec.Length)
	case v1alpha.AlgorithmAES128:
		secretkey.NewAlgPEMKey(secretkey.AES128)
	case v1alpha.AlgorithmAES192:
		secretkey.NewAlgPEMKey(secretkey.AES192)
	case v1alpha.AlgorithmAES256:
		secretkey.NewAlgPEMKey(secretkey.AES256)
	case v1alpha.AlgorithmHMACSHA256:
		secretkey.NewAlgPEMKey(secretkey.HMACSHA256)
	case v1alpha.AlgorithmHMACSHA512:
		secretkey.NewAlgPEMKey(secretkey.HMACSHA512)

	}
	if err != nil {
		return err
	}
	sec.Value = value
	return nil
}

// IsEmpty boolean determines if the struct is empty
func (sec *SecretKey) IsEmpty() bool {
	if len(sec.Value) == 0 {
		return true
	}
	return false

}

// LoadFromData loads data from kubernetes secret
func (sec *SecretKey) LoadFromData(secData map[string][]byte) {
	sec.Value = secData[sec.Name]
	return
}

// ToKubernetes "marshals" object to kubernetes object
func (sec *SecretKey) ToKubernetes(secret *corev1.Secret) {
	// data could be nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[sec.Name] = sec.Value
}

// NewSecret creates new Secret type for reconciliation
func NewSecretKey(keyConfig *v1alpha1.KeyConfig) *Secret {
	password := &SecretKey{
		Name:   keyConfig.Name,
		V1Spec: keyConfig,
	}
	return password
}
