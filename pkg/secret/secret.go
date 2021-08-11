package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
)

// EncodeType type for pem type field.
type EncodeType string

const (
	GenericKey EncodeType = "GENERIC SECRET"
	AESKey     EncodeType = "AES SECRET KEY"
	HMACKey    EncodeType = "HMAC SECRET KEY"
)

// KeySize is how many bytes that will be generated
type KeySize int

const (
	AES128     KeySize = 16
	AES192     KeySize = 24
	AES256     KeySize = 32
	HMACSHA256 KeySize = 256
	HMACSHA512 KeySize = 512
)

func makeBits(size int) ([]byte, error) {
	secretBits := make([]byte, size)
	_, err := rand.Read(secretBits)
	if err != nil {
		return make([]byte, size), err
	}
	return secretBits, nil
}

// NewGenericPEMKey Creates a new new random secret in
// PEM format type of GENERIC SECRET
func NewGenericPEMKey(size int) ([]byte, error) {
	buffer := bytes.Buffer{}
	secretBits, err := makeBits(size)
	if err != nil {
		return make([]byte, size), err
	}
	block := &pem.Block{
		Type:  string(GenericKey),
		Bytes: secretBits,
	}
	if err := pem.Encode(&buffer, block); err != nil {
		return make([]byte, 0), err
	}
	return buffer.Bytes(), nil
}

// NewAESPEMKey Creates new random secret in PEM format for use with AES ciphers.
func NewAESPEMKey(keySize AESKeySize) ([]byte, error) {
	buffer := bytes.Buffer{}
	secretBits, err := makeBits(int(keySize))
	if err != nil {
		return make([]byte, 0), err
	}
	block := &pem.Block{
		Type:  string(GenericKey),
		Bytes: secretBits,
	}
	if err := pem.Encode(&buffer, block); err != nil {
		return make([]byte, 0), err
	}
	return buffer.Bytes(), nil
}
