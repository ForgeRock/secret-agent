package generator

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"software.sslmate.com/src/go-pkcs12"
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
	for index, key := range ts.refDataKeys {
		if value, ok := data[fmt.Sprintf("%s/%s", ts.refKeys[index], key)]; ok {
			ts.refData = append(ts.refData, value...)
		} else {
			return errors.New(fmt.Sprintf("Reference Data Not Foundi for key: %s", key))
		}
	}
	return nil
}

// LoadSecretFromManager populates truststore data from secret manager
func (ts *TrustStore) LoadSecretFromManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	var err error
	// Maximum secret size is 65k. Need to split the binary data into chunks
	var maxChunks, chunkID uint64
	var truststoreFmt string

	truststoreFmt = fmt.Sprintf("%s_%s_%s_numChunks", namespace, secretName, ts.Name)
	chunkIDByte, err := secretsmanager.LoadSecret(context, config, truststoreFmt)
	if err != nil {
		return err
	}
	if len(chunkIDByte) == 0 {
		return nil
	}
	maxChunks = uint64(binary.LittleEndian.Uint64(chunkIDByte))
	for chunkID = 0; chunkID <= maxChunks; chunkID++ {
		truststoreFmt = fmt.Sprintf("%s_%s_%s_%d", namespace, secretName, ts.Name, chunkID)
		chunk, err := secretsmanager.LoadSecret(context, config, truststoreFmt)
		if err != nil {
			return err
		}
		ts.Value = append(ts.Value, chunk...)

	}
	return nil

}

// EnsureSecretManager stores truststore data in secret manager
func (ts *TrustStore) EnsureSecretManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	// Maximum secret size is 65k. Need to split the binary data into chunks
	var chunkSize int = 65536
	var chunkID uint64 = 0
	var chunkIDByte []byte
	var chunk []byte
	var truststoreFmt string
	// copy the slice to a new one
	var data []byte = append([]byte(nil), ts.Value...)
	for chunkSize < len(data) {
		data, chunk = data[chunkSize:], data[0:chunkSize:chunkSize]
		truststoreFmt = fmt.Sprintf("%s_%s_%s_%d", namespace, secretName, ts.Name, chunkID)
		if err := secretsmanager.EnsureSecret(context, config, truststoreFmt, chunk); err != nil {
			return err
		}
		chunkID++
	}
	truststoreFmt = fmt.Sprintf("%s_%s_%s_%d", namespace, secretName, ts.Name, chunkID)
	if err := secretsmanager.EnsureSecret(context, config, truststoreFmt, data); err != nil {
		return err
	}
	// Store the number of chunks. This will be useful when we need to load data from the secret manager
	chunkIDByte = make([]byte, 8)
	binary.LittleEndian.PutUint64(chunkIDByte, uint64(chunkID))
	truststoreFmt = fmt.Sprintf("%s_%s_%s_numChunks", namespace, secretName, ts.Name)
	if err := secretsmanager.EnsureSecret(context, config, truststoreFmt, chunkIDByte); err != nil {
		return err
	}
	return nil
}

// Generate  and all of its aliases
func (ts *TrustStore) Generate() error {
	systemBundle, err := ioutil.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		return errors.WithMessage(err, "error occured when attempting to read system trust store")
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
