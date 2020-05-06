package generator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

func generateRSAPrivateKey() (*rsa.PrivateKey, []byte, error) {
	reader := rand.Reader
	privateKey, err := rsa.GenerateKey(reader, 2048)
	if err != nil {
		return privateKey, []byte{}, errors.WithStack(err)
	}

	buffer := &bytes.Buffer{}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	err = pem.Encode(buffer, block)
	if err != nil {
		return privateKey, []byte{}, errors.WithStack(err)
	}
	privateKeyBytes := buffer.Bytes()

	return privateKey, privateKeyBytes, nil
}

func generateRSAPublicKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}
	buffer := &bytes.Buffer{}
	err := pem.Encode(buffer, block)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	publicKeyBytes := buffer.Bytes()

	return publicKeyBytes, nil
}

func generateRSAPublicKeySSH(privateKey *rsa.PrivateKey) ([]byte, error) {
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return []byte{}, err
	}

	publicKeyBytes := ssh.MarshalAuthorizedKey(pub)

	return publicKeyBytes, nil
}
