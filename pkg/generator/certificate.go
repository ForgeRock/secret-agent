package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/ForgeRock/secret-agent/api/v1alpha1"
	"github.com/pkg/errors"
)

// Certificate represents a certificate and its private key
type Certificate struct {
	Cert          *x509.Certificate
	CertPEM       []byte
	PrivateKeyEC  *ecdsa.PrivateKey
	PrivateKeyRSA *rsa.PrivateKey
	PrivateKeyPEM []byte
}

// GenerateRootCA Generates a root CA
func GenerateRootCA(commonName string) (*Certificate, error) {
	var err error
	cert := &Certificate{}

	// PrivateKeyEC and PrivateKeyPEM
	cert.PrivateKeyEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cert, errors.WithStack(err)
	}
	// TODO Which way do we want to marshal?
	// marshaledPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(cert.PrivateKeyEC)
	if err != nil {
		return cert, errors.WithStack(err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey}
	cert.PrivateKeyPEM = pem.EncodeToMemory(block)

	// prepare cert template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cert, errors.WithStack(err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(10 * 365 * 24 * time.Hour), // + 10 years
		IsCA:               true,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Cert and CertPEM
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &cert.PrivateKeyEC.PublicKey, cert.PrivateKeyEC)
	if err != nil {
		return cert, errors.WithStack(err)
	}
	cert.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	block, _ = pem.Decode(cert.CertPEM)
	if block == nil {
		return cert, errors.WithStack(errors.New("Unable to decode PEM encoded cert"))
	}
	// need to use the parsed cert, not the template
	cert.Cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return cert, errors.WithStack(err)
	}

	return cert, nil
}

// GenerateSignedCert issues a certificate signed by the provided root CA
func GenerateSignedCert(rootCA *Certificate, algorithm v1alpha1.Algorithm, commonName string, sans []string) (*Certificate, error) {
	var err error
	cert := &Certificate{}

	// PrivateKeyEC/PrivateKeyRSA and PrivateKeyPEM
	switch algorithm {
	case v1alpha1.ECDSAWithSHA256:
		cert.PrivateKeyEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return cert, errors.WithStack(err)
		}

		marshaledPrivateKey, err := x509.MarshalECPrivateKey(cert.PrivateKeyEC)
		if err != nil {
			return cert, errors.WithStack(err)
		}
		cert.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})
	case v1alpha1.SHA256WithRSA:
		cert.PrivateKeyRSA, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return cert, errors.WithStack(err)
		}

		marshaledPrivateKey := x509.MarshalPKCS1PrivateKey(cert.PrivateKeyRSA)
		cert.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: marshaledPrivateKey})
	}

	// prepare cert template
	notBefore := time.Now().Add(time.Minute * -5)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10yrs
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cert, errors.WithStack(err)
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
	if len(commonName) != 0 {
		certTemplate.Subject = pkix.Name{
			CommonName: commonName,
		}
	}
	for _, hostname := range sans {
		if ip := net.ParseIP(hostname); ip != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		} else {
			certTemplate.DNSNames = append(certTemplate.DNSNames, hostname)
		}
	}

	// CertPEM
	var publicKey interface{}
	switch algorithm {
	case v1alpha1.ECDSAWithSHA256:
		publicKey = &cert.PrivateKeyEC.PublicKey
	case v1alpha1.SHA256WithRSA:
		publicKey = &cert.PrivateKeyRSA.PublicKey
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCA.Cert, publicKey, rootCA.PrivateKeyEC)
	if err != nil {
		return cert, errors.WithStack(err)
	}
	cert.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	block, _ := pem.Decode(cert.CertPEM)
	if block == nil {
		return cert, errors.WithStack(errors.New("Unable to decode PEM encoded cert"))
	}
	// need to use the parsed cert, not the template
	cert.Cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return cert, errors.WithStack(err)
	}
	return cert, nil
}

// GenerateSharedCertPEM generates a "non-conforming" certificate that's intended to not be used in PKI or any application unless explicitly designed to share keys.
func GenerateSharedCertPEM(commonName string) ([]byte, []byte, []byte, error) {
	var err error
	cert := &Certificate{}
	cert.PrivateKeyRSA, err = rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, errors.WithStack(errors.New("Unable to generate RSA key"))
	}
	marshaledPrivateKey := x509.MarshalPKCS1PrivateKey(cert.PrivateKeyRSA)
	cert.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: marshaledPrivateKey})
	// prepare cert template
	notBefore := time.Unix(0, 0)
	notAfter := time.Unix(0, 1)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, errors.WithStack(errors.New("Unable to create serial number for cert"))
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	if len(commonName) != 0 {
		certTemplate.Subject = pkix.Name{
			CommonName: commonName,
		}
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &cert.PrivateKeyRSA.PublicKey, cert.PrivateKeyRSA)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, errors.WithStack(err)
	}
	cert.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certAndKeyPEM := append(cert.CertPEM, cert.PrivateKeyPEM...)
	return certAndKeyPEM, cert.CertPEM, cert.PrivateKeyPEM, nil
}

// GenerateSignedCertPEM issues a certificate signed by the provided root CA
//   receives and returns PEM version
func GenerateSignedCertPEM(rootCAPEM, rootCAPrivateKeyPEM []byte, algorithm v1alpha1.Algorithm, commonName string, sans []string) ([]byte, []byte, []byte, error) {
	// root CA
	block, _ := pem.Decode(rootCAPEM)
	if block == nil {
		return []byte{}, []byte{}, []byte{}, errors.WithStack(errors.New("Unable to decode PEM encoded cert"))
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, errors.WithStack(err)
	}

	// root private key
	block, _ = pem.Decode(rootCAPrivateKeyPEM)
	if block == nil {
		return []byte{}, []byte{}, []byte{}, errors.WithStack(errors.New("Unable to decode PEM encoded cert"))
	}
	parsedPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, errors.WithStack(err)
	}

	// generate
	rootCA := &Certificate{Cert: parsedCert, PrivateKeyEC: parsedPrivateKey}
	cert, err := GenerateSignedCert(rootCA, algorithm, commonName, sans)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	// setup return values
	certAndKeyPEM := append(cert.CertPEM, cert.PrivateKeyPEM...)

	return certAndKeyPEM, cert.CertPEM, cert.PrivateKeyPEM, nil
}
