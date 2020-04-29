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
	"time"

	"github.com/ForgeRock/secret-agent/pkg/types"
)

func generateCA(alias *types.AliasConfig) ([]byte, error) {
	signatureAlgorithm := x509.SignatureAlgorithm(0)
	switch alias.Algorithm {
	case "ECDSAWithSHA256":
		signatureAlgorithm = x509.ECDSAWithSHA256
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			CommonName: alias.CommonName,
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(10, 0, 0), // + 10 years
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
		return []byte{}, err
	}

	ca, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return ca, err
	}
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca,
	})
	// TODO do we need caPrivateKeyPEM?
	// marshaledPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	// if err != nil {
	//     return ca, err
	// }
	// caPrivateKeyPEM := new(bytes.Buffer)
	// pem.Encode(caPrivateKeyPEM, &pem.Block{
	//     Type:  "RSA PRIVATE KEY",
	//     Bytes: marshaledPrivateKey,
	// })

	return caPEM.Bytes(), nil
}
