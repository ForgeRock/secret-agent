package generator

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	"github.com/pkg/errors"
)

// Literal randomly generated of specified length
type Literal struct {
	Name        string
	Value       []byte
	ConfigValue []byte
	IsBase64    bool
}

// References return names of secrets that should be looked up
func (literal *Literal) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads references from data
func (literal *Literal) LoadReferenceData(data map[string][]byte) error {
	return nil
}

// LoadSecretFromManager populates Literal data from secret manager
func (literal *Literal) LoadSecretFromManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	var err error
	literalFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, literal.Name)
	literal.Value, err = sm.LoadSecret(context, literalFmt)
	if err != nil {
		return err
	}
	return nil
}

// EnsureSecretManager populates secrets manager from Literal data
func (literal *Literal) EnsureSecretManager(context context.Context, sm secretsmanager.SecretManager, secretManagerKeyNamespace string) error {
	var err error
	literalFmt := fmt.Sprintf("%s_%s", secretManagerKeyNamespace, literal.Name)
	err = sm.EnsureSecret(context, literalFmt, literal.Value)
	if err != nil {
		return err
	}
	return nil
}

// InSecret return true if the key is one found in the secret
func (literal *Literal) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[literal.Name] == nil || literal.IsEmpty() {
		if secObject.Data[literal.Name] == nil {
			return false
		}
		return false
	}
	if bytes.Compare(literal.Value, secObject.Data[literal.Name]) == 0 {
		return true
	}
	return false

}

// Generate generates data
func (literal *Literal) Generate() error {
	var err error
	if literal.IsBase64 {
		literal.Value, err = base64.StdEncoding.DecodeString(string(literal.ConfigValue))
		if err != nil {
			return errors.New("A value was not provided or coudln't be decoded")
		}
		return nil
	}
	literal.Value = literal.ConfigValue
	return nil
}

// IsEmpty boolean determines if the struct is empty
func (literal *Literal) IsEmpty() bool {
	if len(literal.Value) == 0 {
		return true
	}
	return false

}

// LoadFromData loads data from kubernetes secret
func (literal *Literal) LoadFromData(secData map[string][]byte) {
	literal.Value = secData[literal.Name]
	return
}

// ToKubernetes "marshals" object to kubernetes object
func (literal *Literal) ToKubernetes(secret *corev1.Secret) {
	// data could be nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[literal.Name] = literal.Value
}

// NewLiteral creates new Literal type for reconciliation
func NewLiteral(keyConfig *v1alpha1.KeyConfig) *Literal {
	literal := &Literal{
		Name:        keyConfig.Name,
		ConfigValue: []byte(keyConfig.Spec.Value),
		IsBase64:    keyConfig.Spec.IsBase64,
	}
	return literal
}
