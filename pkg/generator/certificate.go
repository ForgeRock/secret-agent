package generator

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/ForgeRock/secret-agent/pkg/secretsmanager"
)

var (
	errCertDecode error = errors.New("PEM data couldn't be decoded")
)

// Certificate represents a certificate and its private key
type Certificate struct {
	Cert          *x509.Certificate
	CertPEM       []byte
	PrivateKeyEC  *ecdsa.PrivateKey
	PrivateKeyRSA *rsa.PrivateKey
	PrivateKeyPEM []byte
}

func configureExpire(certTemplate *x509.Certificate, d *metav1.Duration) {
	// meta duration has time.Duration
	var duration time.Duration
	currentTime := time.Now()
	// default for CA is 100
	if d == nil && certTemplate.IsCA {
		duration = 100 * 365 * 24 * time.Hour // 100 years
	} else if d == nil {
		duration = 10 * 365 * 24 * time.Hour // 10 years
	} else if d != nil {
		duration = d.Duration
	}

	notBefore := time.Now().Add(time.Minute * -5)
	notAfter := currentTime.Add(duration)
	// forcing an expired/unusable cert
	// use case for expired: expired certs can be used for encryption but not intended to be part of PKI.
	// In the event the cert gets used as part of PKI setup, the clients should reject the cert.
	// They are used for sharing encrypted data between instances of applications.
	// _note:_ see configureUsage
	// if the current time is after the end of the certificates valid date then make the certificate valid duration to be unusable.
	if currentTime.After(notAfter) {
		notBefore, _ = time.Parse("2006-Jan-02", "1970-Jan-01")
		notAfter, _ = time.Parse("2006-Jan-02", "1970-Jan-02")
	}
	certTemplate.NotAfter = notAfter
	certTemplate.NotBefore = notBefore

}

func configureUsage(certTemplate *x509.Certificate) {
	if certTemplate.IsCA {
		certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		return
	}
	// forcing an expired/unusable cert
	// use case for expired: expired certs can be used for encryption but not intended to be part of PKI.
	// In the event the cert gets used as part of PKI setup, the clients should reject the cert.
	// They are used for sharing encrypted data between instances of applications.
	// _note:_ see configureExpire
	// configure cert for only signatures
	if certTemplate.NotAfter.Before(time.Now()) {
		return

	}
	// default configuration of usage
	certTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

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

func keyPairFromPemBytes(publicKeyPem []byte, privateKeyPem []byte) (*x509.Certificate, interface{}, error) {
	// convert back from PEM
	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}

	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}
	ecPrivateKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
	rsaPrivateKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
	if ecErr != nil && rsaErr != nil {
		return &x509.Certificate{}, &ecdsa.PrivateKey{}, errCertDecode
	}
	if rsaErr != nil {
		return parsedCert, ecPrivateKey, nil
	}
	return parsedCert, rsaPrivateKey, nil
}

// CertKeyPair Private/Public certificates which optionally can be signed by a RootCA
type CertKeyPair struct {
	Name        string
	RootCA      *CertKeyPair
	Cert        *Certificate
	V1Spec      *v1alpha1.KeySpec
	refName     string
	refDataKeys []string
	refValue    []byte
	isCA        bool
}

// References return names of secrets that should be looked up
func (kp *CertKeyPair) References() ([]string, []string) {
	if kp.RootCA != nil {
		return []string{kp.refName, kp.refName}, kp.refDataKeys
	}
	return []string{}, []string{}
}

// LoadSecretFromManager populates RootCA data from secret manager
func (kp *CertKeyPair) LoadSecretFromManager(ctx context.Context, sm secretsmanager.SecretManager, namespace, secretName string) error {
	var err error
	publicPemKeyFmt := fmt.Sprintf("%s_%s_%s.pem", namespace, secretName, kp.Name)
	privatePemKeyFmt := fmt.Sprintf("%s_%s_%s-private.pem", namespace, secretName, kp.Name)

	kp.Cert.CertPEM, err = sm.LoadSecret(ctx, publicPemKeyFmt)
	if err != nil {
		return err
	}
	kp.Cert.PrivateKeyPEM, err = sm.LoadSecret(ctx, privatePemKeyFmt)
	if err != nil {
		return err
	}
	return nil
}

// EnsureSecretManager populates secrete manager from RootCA data
func (kp *CertKeyPair) EnsureSecretManager(ctx context.Context, sm secretsmanager.SecretManager, namespace, secretName string) error {
	var err error
	publicPemKeyFmt := fmt.Sprintf("%s_%s_%s.pem", namespace, secretName, kp.Name)
	privatePemKeyFmt := fmt.Sprintf("%s_%s_%s-private.pem", namespace, secretName, kp.Name)
	err = sm.EnsureSecret(ctx, publicPemKeyFmt, kp.Cert.CertPEM)
	if err != nil {
		return err
	}
	err = sm.EnsureSecret(ctx, privatePemKeyFmt, kp.Cert.PrivateKeyPEM)
	if err != nil {
		return err
	}
	return nil

}

// InSecret return true if the key is one found in the secret
func (kp *CertKeyPair) InSecret(secObject *corev1.Secret) bool {

	publicPemKey := fmt.Sprintf("%s.pem", kp.Name)
	privatePemKey := fmt.Sprintf("%s-private.pem", kp.Name)
	combinedPemKey := fmt.Sprintf("%s-combined.pem", kp.Name)
	if secObject.Data == nil || secObject.Data[publicPemKey] == nil ||
		secObject.Data[privatePemKey] == nil || secObject.Data[combinedPemKey] == nil ||
		kp.IsEmpty() {
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

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.WithStack(err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		BasicConstraintsValid: true,
		IsCA:                  kp.isCA,
	}

	// valid dates
	configureExpire(certTemplate, kp.V1Spec.Duration)

	// key usage and extended usage
	configureUsage(certTemplate)

	// add subject
	pkixName := dnToPkixName(kp.V1Spec.DistinguishedName)
	if pkixName != nil {
		certTemplate.Subject = *pkixName
	}

	// add sans
	for _, hostname := range kp.V1Spec.Sans {
		if ip := net.ParseIP(hostname); ip != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		} else {
			certTemplate.DNSNames = append(certTemplate.DNSNames, hostname)
		}
	}

	// public key
	var publicKey interface{}
	switch kp.V1Spec.Algorithm {
	case v1alpha1.AlgorithmTypeECDSAWithSHA256:
		publicKey = &kp.Cert.PrivateKeyEC.PublicKey
	case v1alpha1.AlgorithmTypeSHA256WithRSA:
		publicKey = &kp.Cert.PrivateKeyRSA.PublicKey
	}

	// handle signing
	var signer crypto.Signer
	var parentCert *Certificate

	if !kp.isCA && !kp.V1Spec.SelfSigned {
		parentCert = kp.RootCA.Cert
	} else {
		// this is a CA or Self signed
		parentCert = kp.Cert
		parentCert.Cert = certTemplate
	}

	// self signed certs can use either alg for signing
	if parentCert.PrivateKeyEC != nil {
		signer = parentCert.PrivateKeyEC
	} else if parentCert.PrivateKeyRSA != nil {
		signer = parentCert.PrivateKeyRSA
	}
	// our RooCA is always ECDSA
	// handle encoding
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, parentCert.Cert, publicKey, signer)
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
	var ok bool
	if kp.Cert.CertPEM, ok = data[pubKey]; !ok {
		return
	}
	if kp.Cert.PrivateKeyPEM, ok = data[privKey]; !ok {
		return
	}
	var privateKey interface{}
	var err error
	kp.Cert.Cert, privateKey, err = keyPairFromPemBytes(kp.Cert.CertPEM, kp.Cert.PrivateKeyPEM)
	if err != nil {
		log.Printf("error decoding %s", err)
	}

	switch priv := privateKey.(type) {
	case *ecdsa.PrivateKey:
		kp.Cert.PrivateKeyEC = priv
		kp.V1Spec.Algorithm = v1alpha1.AlgorithmTypeECDSAWithSHA256
	case *rsa.PrivateKey:
		kp.Cert.PrivateKeyRSA = priv
		kp.V1Spec.Algorithm = v1alpha1.AlgorithmTypeSHA256WithRSA
	}
	return
}

// IsEmpty checks if CertKeyPair has any useable
func (kp *CertKeyPair) IsEmpty() bool {
	if kp.Cert.CertPEM == nil || kp.Cert.PrivateKeyPEM == nil {
		return true
	}
	if len(kp.Cert.CertPEM) == 0 || len(kp.Cert.PrivateKeyPEM) == 0 {
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
	combinedPemKey := fmt.Sprintf("%s-combined.pem", kp.Name)
	secObject.Data[publicPemKey] = kp.Cert.CertPEM
	secObject.Data[privatePemKey] = kp.Cert.PrivateKeyPEM
	secObject.Data[combinedPemKey] = append(kp.Cert.CertPEM, kp.Cert.PrivateKeyPEM...)
	return
}

// LoadReferenceData loads references from data
func (kp *CertKeyPair) LoadReferenceData(data map[string][]byte) error {
	// ca's and self singed don't use references
	if kp.V1Spec.SelfSigned || kp.isCA {
		return nil
	}
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

// NewCertKeyPair creates new CertKeyPair type for reconciliation
func NewCertKeyPair(keyConfig *v1alpha1.KeyConfig) (*CertKeyPair, error) {
	keyPair := &CertKeyPair{
		Cert: &Certificate{},
		Name: keyConfig.Name,
	}
	secretRef, dataKey := handleRefPath(keyConfig.Spec.SignedWithPath)
	selfSigned := &keyConfig.Spec.SelfSigned != nil && keyConfig.Spec.SelfSigned == true
	// setup for signing
	if !selfSigned {
		rCAKeyConfig := &v1alpha1.KeyConfig{
			Name: dataKey,
			Type: v1alpha1.KeyConfigTypeCA,
			Spec: &v1alpha1.KeySpec{},
		}
		rCA := NewRootCA(rCAKeyConfig)
		keyPair.RootCA = rCA
		keyPair.refName = secretRef
		keyPair.refDataKeys = []string{fmt.Sprintf("%s.pem", dataKey), fmt.Sprintf("%s-private.pem", dataKey)}
	} else if !selfSigned && secretRef == "" {
		return &CertKeyPair{}, errors.New("expected to find path to a signing key")
	}
	keyPair.V1Spec = keyConfig.Spec
	return keyPair, nil
}

// NewRootCA create a cert that is a root signing CA
func NewRootCA(keyConfig *v1alpha1.KeyConfig) *CertKeyPair {
	rCA := &CertKeyPair{
		Name: keyConfig.Name,
		isCA: true,
		Cert: &Certificate{},
	}
	rCA.V1Spec = keyConfig.Spec
	if rCA.V1Spec.Algorithm == "" {
		rCA.V1Spec.Algorithm = v1alpha1.AlgorithmTypeECDSAWithSHA256
	}
	return rCA
}
