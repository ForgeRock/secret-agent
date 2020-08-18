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

var (
	errCertDecode error = errors.New("PEM data couldn't be decoded")
)

func keyPairFromPemBytes(publicKeyPem []byte, privateKeyPem []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// convert back from PEM
	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}

	// root private key
	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}
	parsedPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}
	return parsedCert, parsedPrivateKey, nil

}

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
	Name        string
	RootCA      *RootCA
	Cert        *Certificate
	V1Spec      *v1alpha1.KeySpec
	SelfSigned  bool
	refName     string
	refDataKeys []string
	refValue    []byte
}

// References return names of secrets that should be looked up
func (kp *CertKeyPair) References() ([]string, []string) {
	return []string{kp.refName, kp.refName}, kp.refDataKeys
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
	// setup expire
	// prepare cert template
	currentTime := time.Now()
	notBefore := time.Now().Add(time.Minute * -5)
	notAfter := currentTime.Add(kp.V1Spec.Duration.Duration)

	// forcing an expired/unusable cert
	// use case for expired: expired certs can be used for encryption but not intended to be part of PKI.
	// In the event the cert gets used as part of PKI setup, the clients should reject the cert.
	// They are used for sharing encrypted data between instances of applications.
	//
	// if the current time is after the end of the certificates valid date then make the certificate valid duration to be unusable.
	if currentTime.After(notAfter) {
		notBefore, _ = time.Parse("0000-Jan-01", "0000-Jan-01")
		notAfter, _ = time.Parse("0000-Jan-01", "0000-Jan-02")
	}

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
	// self sign or root signed
	var signer *x509.Certificate
	var signerPrivate interface{}
	if kp.V1Spec.SelfSigned {
		signer = certTemplate
		// self signed certs can use either alg for signing
		switch kp.V1Spec.Algorithm {
		case v1alpha1.AlgorithmTypeECDSAWithSHA256:
			signerPrivate = kp.Cert.PrivateKeyEC
		case v1alpha1.AlgorithmTypeSHA256WithRSA:
			signerPrivate = kp.Cert.PrivateKeyRSA
		}
	} else {
		// our RooCA is always ECDSA
		signer = kp.RootCA.Cert.Cert
		signerPrivate = kp.RootCA.Cert.PrivateKeyEC
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, signer, publicKey, signerPrivate)
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
	rootData := make(map[string][]byte, 2)
	for _, refDataKey := range kp.refDataKeys {
		rootData[refDataKey] = data[fmt.Sprintf("%s/%s", kp.refName, refDataKey)]
	}
	kp.RootCA.LoadFromData(rootData)
	if kp.RootCA.IsEmpty() {
		return errors.New("signing CA couldn't be loaded")
	}
	return nil
}

// NewCertKeyPair creates new CertKeyPair type for reconcilation
func NewCertKeyPair(keyConfig *v1alpha1.KeyConfig) (*CertKeyPair, error) {
	secretRef, dataKey := handleRefPath(keyConfig.Spec.SignedWithPath)
	rootCA := &RootCA{
		Name:           secretRef,
		Cert:           &Certificate{},
		privateKeyName: fmt.Sprintf("%s-private.pem", dataKey),
		publicKeyName:  fmt.Sprintf("%s.pem", dataKey),
	}
	keyPair := &CertKeyPair{
		Cert:   &Certificate{},
		RootCA: rootCA,
	}
	keyPair.Name = keyConfig.Name
	keyPair.refName = secretRef
	keyPair.refDataKeys = []string{fmt.Sprintf("%s.pem", dataKey), fmt.Sprintf("%s-private.pem", dataKey)}
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
