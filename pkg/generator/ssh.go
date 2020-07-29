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

func generateRSAPrivateKey() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	buffer := &bytes.Buffer{}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	err = pem.Encode(buffer, block)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	return buffer.Bytes(), nil
}

func getRSAPublicKeyFromPrivateKey(privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return []byte{}, errors.WithStack(errors.New("failed to decode PEM block containing private key"))
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	block = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}
	buffer := &bytes.Buffer{}
	err = pem.Encode(buffer, block)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	return buffer.Bytes(), nil
}

func getRSAPublicKeySSHFromPrivateKey(privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return []byte{}, errors.WithStack(errors.New("failed to decode PEM block containing private key"))
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	return ssh.MarshalAuthorizedKey(publicKey), nil
}
