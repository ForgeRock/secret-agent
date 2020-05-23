package generator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/ForgeRock/secret-agent/api/v1alpha1"
)

// RootCA data trasfer object for root CAs
type RootCA struct {
	CAPem           []byte
	CAPrivateKeyPEM []byte
	CA              *x509.Certificate
	CAKey           *ecdsa.PrivateKey
}

// GenerateRootCA Generates a root CA
func GenerateRootCA(algorithm v1alpha1.Algorithm, commonName string) (RootCA, error) {
	signatureAlgorithm := x509.SignatureAlgorithm(0)
	switch algorithm {
	case v1alpha1.ECDSAWithSHA256:
		signatureAlgorithm = x509.ECDSAWithSHA256
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return RootCA{}, errors.WithStack(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(10 * 365 * 24 * time.Hour), // + 10 years
		IsCA:               true,
		SignatureAlgorithm: signatureAlgorithm,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RootCA{}, errors.WithStack(err)
	}

	ca, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return RootCA{}, errors.WithStack(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})

	// TODO Which way do we want to marshal?
	// marshaledPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	marshaledPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return RootCA{}, errors.WithStack(err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey}
	caPrivateKeyPEM := pem.EncodeToMemory(block)

	return RootCA{CAPem: caPEM, CAPrivateKeyPEM: caPrivateKeyPEM, CA: caTemplate, CAKey: privateKey}, nil
}

// GenerateSignedCert issues a certificate signed by the provided root CA
func GenerateSignedCert(rootCA RootCA, hosts []string) ([]byte, []byte, error) {
	cert, key := []byte{}, []byte{}
	notBefore := time.Now().Add(time.Minute * -5)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) //10yrs

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cert, key, errors.WithStack(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cert, key, errors.WithStack(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, ip)
		} else {
			leafTemplate.DNSNames = append(leafTemplate.DNSNames, h)
		}
	}

	leaf, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCA.CA, &leafKey.PublicKey, rootCA.CAKey)
	if err != nil {
		return cert, key, errors.WithStack(err)
	}

	block := &pem.Block{Type: "CERTIFICATE", Bytes: leaf}
	cert = pem.EncodeToMemory(block)

	marshaledPrivateKey, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return cert, key, errors.WithStack(err)
	}
	block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey}
	key = pem.EncodeToMemory(block)

	return cert, key, nil
}

// GetECPublicKeyFromPrivateKey gets a public key from an ECDSA private key
func GetECPublicKeyFromPrivateKey(privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return []byte{}, errors.WithStack(errors.New("failed to decode PEM block containing private key"))
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	mashaledPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	block = &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: mashaledPublicKey,
	}
	buffer := &bytes.Buffer{}
	err = pem.Encode(buffer, block)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	return buffer.Bytes(), nil
}
