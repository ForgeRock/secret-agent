package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

//RootCA data trasfer object for root CAs
type RootCA struct {
	CAPem           []byte
	CAPrivateKeyPEM []byte
	CA              *x509.Certificate
	CAKey           *ecdsa.PrivateKey
}

//GenerateRootCA Generates a root CA
func GenerateRootCA(algorithm string, commonName string) (RootCA, error) {
	signatureAlgorithm := x509.SignatureAlgorithm(0)
	switch algorithm {
	case "ECDSAWithSHA256":
		signatureAlgorithm = x509.ECDSAWithSHA256
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return RootCA{}, err
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
		return RootCA{}, err
	}

	ca, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return RootCA{}, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca})

	marshaledPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return RootCA{}, err
	}
	caPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledPrivateKey})

	//TODO: Which way do we want to encode the PEM for the ca?
	// marshaledPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	// if err != nil {
	// 	return caPEM, []byte{}, err
	// }
	// caPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: marshaledPrivateKey})

	return RootCA{CAPem: caPEM, CAPrivateKeyPEM: caPrivateKeyPEM, CA: caTemplate, CAKey: privateKey}, nil
}

// GenerateSignedCerts issues a certificate signed by the provided root CA
func GenerateSignedCerts(rootCA RootCA, hosts []string) (cert []byte, key []byte, err error) {
	notBefore := time.Now().Add(time.Minute * -5)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) //10yrs

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return []byte{}, []byte{}, err
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
		return []byte{}, []byte{}, err
	}

	cert = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaf})

	marshaledPrivateKey, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	key = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: marshaledPrivateKey})
	return cert, key, nil
}
