package generator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

// Certificate represents a certificate and its private key
type Certificate struct {
	Cert          *x509.Certificate
	CertPEM       []byte
	PrivateKeyEC  *ecdsa.PrivateKey
	PrivateKeyRSA *rsa.PrivateKey
	PrivateKeyPEM []byte
}

// CertKeyPair Private/Public certificates which optionally can be signed by a RootCA
type CertKeyPair struct {
	Name       string
	RootCA     *RootCA
	Cert       *Certificate
	V1Spec     *v1alpha1.KeySpec
	SelfSigned bool
	refName    string
	refDataKey string
	refValue   []byte
}

// References return names of secrets that should be looked up
func (kp *CertKeyPair) References() ([]string, []string) {
	return []string{kp.refName}, []string{kp.refDataKey}
}

// LoadSecretFromManager populates CertKeyPair data from secret manager
func (kp *CertKeyPair) LoadSecretFromManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// EnsureSecretManager populates secrete manager from CertKeyPair data
func (kp *CertKeyPair) EnsureSecretManager(context context.Context, config *v1alpha1.AppConfig, namespace, secretName string) error {
	return nil
}

// InSecret return true if the key is one found in the secret
func (kp *CertKeyPair) InSecret(secObject *corev1.Secret) bool {

	publicPemKey := fmt.Sprintf("%s.pem", kp.Name)
	privatePemKey := fmt.Sprintf("%s-private.pem", kp.Name)
	if secObject.Data == nil || secObject.Data[publicPemKey] == nil ||
		secObject.Data[privatePemKey] == nil || kp.IsEmpty() {
		return false
	}
	if bytes.Compare(secObject.Data[publicPemKey], kp.Cert.CertPEM) == 0 &&
		bytes.Compare(secObject.Data[privatePemKey], kp.Cert.PrivateKeyPEM) == 0 {
		return true
	}
	return false
}

// Generate generate a key pair
func (kp *CertKeyPair) Generate() error {
	var err error

	// PrivateKeyEC/PrivateKeyRSA and PrivateKeyPEM
	switch kp.V1Spec.Algorithm {
	case v1alpha1.AlgorithmTypeECDSAWithSHA256:
		kp.Cert.PrivateKeyEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return errors.WithStack(err)
		}

		marshaledPrivateKey, err := x509.MarshalECPrivateKey(kp.Cert.PrivateKeyEC)
		if err != nil {
			return errors.WithStack(err)
		}
		kp.Cert.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})
	case v1alpha1.AlgorithmTypeSHA256WithRSA:
		kp.Cert.PrivateKeyRSA, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return errors.WithStack(err)
		}

		marshaledPrivateKey := x509.MarshalPKCS1PrivateKey(kp.Cert.PrivateKeyRSA)
		kp.Cert.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: marshaledPrivateKey})
	}
	// prepare cert template
	notBefore := time.Now().Add(time.Minute * -5)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10yrs
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.WithStack(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	pkixName := dnToPkixName(kp.V1Spec.DistinguishedName)
	if pkixName != nil {
		certTemplate.Subject = *pkixName
	}
	for _, hostname := range kp.V1Spec.Sans {
		if ip := net.ParseIP(hostname); ip != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		} else {
			certTemplate.DNSNames = append(certTemplate.DNSNames, hostname)
		}
	}

	// CertPEM
	var publicKey interface{}
	switch kp.V1Spec.Algorithm {
	case v1alpha1.AlgorithmTypeECDSAWithSHA256:
		publicKey = &kp.Cert.PrivateKeyEC.PublicKey
	case v1alpha1.AlgorithmTypeSHA256WithRSA:
		publicKey = &kp.Cert.PrivateKeyRSA.PublicKey
	}
	signer := &Certificate{Cert: kp.RootCA.Cert.Cert,
		PrivateKeyEC: kp.RootCA.Cert.PrivateKeyEC,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, signer.Cert, publicKey, signer.PrivateKeyEC)
	if err != nil {
		return errors.WithStack(err)
	}
	kp.Cert.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	block, _ := pem.Decode(kp.Cert.CertPEM)
	if block == nil {
		return errors.WithStack(errors.New("Unable to decode PEM encoded cert"))
	}
	// need to use the parsed cert, not the template
	kp.Cert.Cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// LoadFromData  load data from kubernetes secret
func (kp *CertKeyPair) LoadFromData(data map[string][]byte) {
	pubKey := fmt.Sprintf("%s.pem", kp.Name)
	privKey := fmt.Sprintf("%s-private.pem", kp.Name)
	// shouldn't happen, but protect against it anyway
	if kp.Cert == nil {
		kp.Cert = &Certificate{}
	}
	kp.Cert.CertPEM, kp.Cert.PrivateKeyPEM = data[pubKey], data[privKey]
	return
}

// IsEmpty checks if CertKeyPair has any useable
func (kp *CertKeyPair) IsEmpty() bool {
	if kp.Cert.CertPEM == nil {
		return true
	}
	if kp.Cert.PrivateKeyPEM == nil {
		return true
	}
	return false
}

// ToKubernetes serializes CertKeyPair to kubernetes object
func (kp *CertKeyPair) ToKubernetes(secObject *corev1.Secret) {
	if secObject.Data == nil {
		secObject.Data = make(map[string][]byte)
	}
	publicPemKey := fmt.Sprintf("%s.pem", kp.Name)
	privatePemKey := fmt.Sprintf("%s-private.pem", kp.Name)
	secObject.Data[publicPemKey] = kp.Cert.CertPEM
	secObject.Data[privatePemKey] = kp.Cert.PrivateKeyPEM
	return
}

// LoadReferenceData loads references from data
func (kp *CertKeyPair) LoadReferenceData(data map[string][]byte) error {
	if len(data) == 0 {
		return errors.New("secret reference value not found")
	}
	rootData := map[string][]byte{
		"ca.pem":         data[fmt.Sprintf("%s/%s", kp.refName, "ca.pem")],
		"ca-private.pem": data[fmt.Sprintf("%s/%s", kp.refName, "ca-private.pem")],
	}
	kp.RootCA.LoadFromData(rootData)
	if kp.RootCA.IsEmpty() {
		return errors.New("signing CA couldn't be loaded")
	}
	return nil
}

// NewCertKeyPair creates new CertKeyPair type for reconcilation
func NewCertKeyPair(keyConfig *v1alpha1.KeyConfig) (*CertKeyPair, error) {
	rootCA := &RootCA{
		Cert: &Certificate{},
	}
	keyPair := &CertKeyPair{
		Cert:   &Certificate{},
		RootCA: rootCA,
	}
	keyPair.Name = keyConfig.Name
	secretRef, dataKey := handleRefPath(keyConfig.Spec.SignedWithPath)
	keyPair.refName = secretRef
	keyPair.refDataKey = dataKey
	keyPair.V1Spec = keyConfig.Spec
	return keyPair, nil
}

// ToPkixName convert DistinguishedName to pkix.Name
func dnToPkixName(dn *v1alpha1.DistinguishedName) *pkix.Name {
	if dn == nil {
		return nil
	}
	return &pkix.Name{Country: dn.Country,
		Organization:       dn.Organization,
		OrganizationalUnit: dn.OrganizationalUnit,
		Locality:           dn.Locality,
		Province:           dn.Province,
		StreetAddress:      dn.StreetAddress,
		PostalCode:         dn.PostalCode,
		SerialNumber:       dn.SerialNumber,
		CommonName:         dn.CommonName,
	}
}
