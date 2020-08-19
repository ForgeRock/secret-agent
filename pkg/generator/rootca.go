package generator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
)

// RootCA root certificate
type RootCA struct {
	Name              string
	ValidDuration     time.Duration
	Cert              *Certificate
	DistinguishedName *v1alpha1.DistinguishedName
	privateKeyName    string
	publicKeyName     string
}

// NewRootCA create new RootCA struct
func NewRootCA(keyConfig *v1alpha1.KeyConfig) (*RootCA, error) {
	cert := &Certificate{}
	rCA := &RootCA{Cert: cert,
		Name:              keyConfig.Name,
		ValidDuration:     keyConfig.Spec.Duration.Duration,
		DistinguishedName: keyConfig.Spec.DistinguishedName,
		publicKeyName:     fmt.Sprintf("%s.pem", keyConfig.Name),
		privateKeyName:    fmt.Sprintf("%s-private.pem", keyConfig.Name),
	}
	return rCA, nil
}

// References return names of secrets that should be looked up
func (rCA *RootCA) References() ([]string, []string) {
	return []string{}, []string{}
}

// LoadReferenceData loads references from data
func (rCA *RootCA) LoadReferenceData(data map[string][]byte) error {
	return nil
}

// LoadSecretFromManager populates RootCA data from secret manager
func (rCA *RootCA) LoadSecretFromManager(ctx context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	var err error
	caPemFmt := fmt.Sprintf("%s_%s_%s", namespace, secretName, rCA.publicKeyName)
	caPrivatePemFmt := fmt.Sprintf("%s_%s_%s", namespace, secretName, rCA.privateKeyName)
	rCA.Cert.CertPEM, err = secretsmanager.LoadSecret(ctx, config, caPemFmt)
	if err != nil {
		return err
	}
	rCA.Cert.PrivateKeyPEM, err = secretsmanager.LoadSecret(ctx, config, caPrivatePemFmt)
	if err != nil {
		return err
	}
	return nil
}

// InSecret return true if the key is one found in the secret
func (rCA *RootCA) InSecret(secObject *corev1.Secret) bool {
	if secObject.Data == nil || secObject.Data[rCA.publicKeyName] == nil ||
		secObject.Data[rCA.privateKeyName] == nil || rCA.IsEmpty() {
		return false
	}
	if bytes.Compare(rCA.Cert.CertPEM, secObject.Data[rCA.publicKeyName]) == 0 &&
		bytes.Compare(rCA.Cert.PrivateKeyPEM, secObject.Data[rCA.privateKeyName]) == 0 {
		return true
	}
	return false

}

// EnsureSecretManager populates secrete manager from RootCA data
func (rCA *RootCA) EnsureSecretManager(ctx context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	var err error
	caPemFmt := fmt.Sprintf("%s_%s_%s", namespace, secretName, rCA.publicKeyName)
	caPrivatePemFmt := fmt.Sprintf("%s_%s_%s", namespace, secretName, rCA.privateKeyName)
	err = secretsmanager.EnsureSecret(ctx, config, caPemFmt, rCA.Cert.CertPEM)
	if err != nil {
		return err
	}
	err = secretsmanager.EnsureSecret(ctx, config, caPrivatePemFmt, rCA.Cert.PrivateKeyPEM)
	if err != nil {
		return err
	}
	return nil

}

// IsEmpty boolean determines if the RootCA struct is empty
func (rCA *RootCA) IsEmpty() bool {
	if rCA.Cert == nil {
		return true
	}
	if len(rCA.Cert.CertPEM) == 0 || len(rCA.Cert.PrivateKeyPEM) == 0 {
		return true
	}
	return false
}

// LoadFromData  load data from kubernetes secret
func (rCA *RootCA) LoadFromData(data map[string][]byte) {
	if rCA.Cert == nil {
		rCA.Cert = &Certificate{}
	}
	if certPem, ok := data[rCA.publicKeyName]; ok {
		rCA.Cert.CertPEM = certPem
	}
	if certPrivatePem, ok := data[rCA.privateKeyName]; ok {
		rCA.Cert.PrivateKeyPEM = certPrivatePem
	}
	var err error
	rCA.Cert.Cert, rCA.Cert.PrivateKeyEC, err = keyPairFromPemBytes(rCA.Cert.CertPEM, rCA.Cert.PrivateKeyPEM)
	if err != nil {
		log.Printf("error decoding %s", err)
	}
}

// ToKubernetes "marshals" object to kubernetes object
func (rCA *RootCA) ToKubernetes(secret *corev1.Secret) {
	// data could be nil
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[rCA.publicKeyName] = rCA.Cert.CertPEM
	secret.Data[rCA.privateKeyName] = rCA.Cert.PrivateKeyPEM
}

// Generate generates data
func (rCA *RootCA) Generate() error {
	var err error

	// PrivateKeyEC and PrivateKeyPEM
	rCA.Cert.PrivateKeyEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.WithStack(err)
	}
	// TODO Which way do we want to marshal?
	// marshaledPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(rCA.Cert.PrivateKeyEC)
	if err != nil {
		return errors.WithStack(err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey}
	rCA.Cert.PrivateKeyPEM = pem.EncodeToMemory(block)

	// prepare cert template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.WithStack(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            rCA.DistinguishedName.Country,
			Organization:       rCA.DistinguishedName.Organization,
			OrganizationalUnit: rCA.DistinguishedName.OrganizationalUnit,
			Locality:           rCA.DistinguishedName.Locality,
			Province:           rCA.DistinguishedName.Province,
			StreetAddress:      rCA.DistinguishedName.StreetAddress,
			PostalCode:         rCA.DistinguishedName.PostalCode,
			SerialNumber:       rCA.DistinguishedName.SerialNumber,
			CommonName:         rCA.DistinguishedName.CommonName,
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(rCA.ValidDuration),
		IsCA:               true,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Cert and CertPEM
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &rCA.Cert.PrivateKeyEC.PublicKey, rCA.Cert.PrivateKeyEC)
	if err != nil {
		return errors.WithStack(err)
	}
	rCA.Cert.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	block, _ = pem.Decode(rCA.Cert.CertPEM)
	if block == nil {
		return errors.WithStack(errors.New("Unable to decode PEM encoded cert"))
	}
	// need to use the parsed cert, not the template
	rCA.Cert.Cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
