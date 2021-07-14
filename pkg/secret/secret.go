package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
)

// EncodeType type for pem type field.
const EncodeType = "GENERIC SECRET"

// NewPEMSecret Creates a new new random secret in
// PEM format type of GENERIC SECRET
func NewPEMSecret(size int) ([]byte, error) {
	buffer := bytes.Buffer{}
	secretBits := make([]byte, size)
	_, err := rand.Read(secretBits)
	if err != nil {
		return make([]byte, size), err
	}
	block := &pem.Block{
		Type:  EncodeType,
		Bytes: secretBits,
	}
	if err := pem.Encode(&buffer, block); err != nil {
		return make([]byte, 0), err
	}
	return buffer.Bytes(), nil
}
