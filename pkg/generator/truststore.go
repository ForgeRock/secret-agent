package generator

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

func parseRootChain(bundle []byte) []*x509.Certificate {
	var parsed []*x509.Certificate
	for len(bundle) > 0 {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		parsed = append(parsed, cert)
	}
	return parsed
}

// NewTrustStore create an new trust store object
func NewTrustStore(key *v1alpha1.KeyConfig) (*TrustStore, error) {
	store := &TrustStore{
		V1Spec: key.Spec,
		Name:   key.Name,
	}
	return store, nil
}

// TrustStore a KeyMgr for managing truststores
type TrustStore struct {
	Name        string
	refKeys     []string
	refDataKeys []string
	refData     []byte
	V1Spec      *v1alpha1.KeySpec
	Value       []byte
}

// References all names the ids of references required for generation
func (ts *TrustStore) References() ([]string, []string) {
	for _, path := range ts.V1Spec.TruststoreImportPaths {
		secretName, secretDataKey := handleRefPath(path)
		ts.refKeys = append(ts.refKeys, secretName)
		// root "certs" magically have a .pem in their data key.
		ts.refDataKeys = append(ts.refDataKeys, fmt.Sprintf("%s.pem", secretDataKey))
	}
	return ts.refKeys, ts.refDataKeys
}

// LoadReferenceData load all alias reference data
func (ts *TrustStore) LoadReferenceData(data map[string][]byte) error {
	for _, key := range ts.refDataKeys {
		if value, ok := data[key]; ok {
			ts.refData = append(ts.refData, value...)
		} else {
			return errors.New(fmt.Sprintf("Reference Data Not Foundi for key: %s", key))
		}
	}
	return nil
}

// LoadSecretFromManager load from secrete manager
func (ts *TrustStore) LoadSecretFromManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// EnsureSecretManager adds  to secret manager
func (ts *TrustStore) EnsureSecretManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// Generate  and all of its aliases
func (ts *TrustStore) Generate() error {
	systemBundle, err := ioutil.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		return errors.WithMessage(err, "error occured when attempting to pull system trust store")
	}
	pemBytes := append(ts.Value, systemBundle...)
	pemBytes = append(pemBytes, ts.refData...)
	parsedCerts := parseRootChain(pemBytes)
	if err != nil {
		return errors.WithStack(err)
	}
	ts.Value, err = pkcs12.EncodeTrustStore(rand.Reader, parsedCerts, "changeit")
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// LoadFromData  from from bytes
func (ts *TrustStore) LoadFromData(secData map[string][]byte) {
	if value, ok := secData[ts.Name]; ok {
		ts.Value = value
	}
}

// IsEmpty test if empty
func (ts *TrustStore) IsEmpty() bool {
	return len(ts.Value) == 0
}

// ToKubernetes serializes data to kubernetes secret
func (ts *TrustStore) ToKubernetes(secObject *corev1.Secret) {
	if secObject.Data == nil {
		secObject.Data = make(map[string][]byte, 1)
	}
	if empty := ts.IsEmpty(); !empty {
		secObject.Data[ts.Name] = ts.Value
	}
}

// InSecret return true if the key is one found in the secret
func (ts *TrustStore) InSecret(secObject *corev1.Secret) bool {
	if _, ok := secObject.Data[ts.Name]; ok {
		return true
	}
	return false
}
