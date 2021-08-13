package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"math/big"

	"github.com/pkg/errors"
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
	// GenericBits random bits of any size
	GenericBits KeySize = iota
	// AES128 128 bit AES key
	AES128 KeySize = 16
	// AES192 192 bit AES key
	AES192 KeySize = 24
	// AES256 256 bit AES key
	AES256 KeySize = 32
	// HMACSHA256 256 bit HMACSHA key
	HMACSHA256 KeySize = 256
	// HMACSHA512 512 bit HMACSHA key
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

func makeReadableBits(size int) ([]byte, error) {
	alphanumericBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	max := big.NewInt(int64(len(alphanumericBytes)))
	bytes := make([]byte, size)
	for i := range bytes {
		randInt, err := rand.Int(rand.Reader, max)
		if err != nil {
			return []byte{}, errors.WithStack(err)
		}
		bytes[i] = alphanumericBytes[int(randInt.Int64())]
	}
	return bytes, nil
}

// NewGenericPEMKey Creates a new new random secret in
// PEM format type of GENERIC SECRET
func NewGenericPEMKey(size int) ([]byte, error) {
	buffer := bytes.Buffer{}
	secretBits, err := makeBits(int(size))
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

// NewAlgPEMKey Creates new random secret in PEM format for use with AES/HMAC ciphers
func NewAlgPEMKey(keyAlg KeySize) ([]byte, error) {
	buffer := bytes.Buffer{}
	secretBits, err := makeBits(int(size))
	if err != nil {
		return make([]byte, 0), err
	}

	switch size {
	case AES128, AES192, AES256:
		pemtype = string(AESKey)
	case HMACSHA256, HMACSHA512:
		pemtype = string(HMACKey)
	}

	block := &pem.Block{
		Type:  pemtype,
		Bytes: secretBits,
	}
	if err := pem.Encode(&buffer, block); err != nil {
		return make([]byte, 0), err
	}
	return buffer.Bytes(), nil
}

// NewSecretBits generate a set of bits that aren't encoded.
// setting binaryBytes to false will result in "readable" secret.
func NewSecretBits(size int, binaryBytes bool) ([]byte, error) {
	if binaryBytes {
		return makeBits(size)
	} else {
		return makeReadableBits(size)
	}
}
