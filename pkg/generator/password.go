package generator

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

// GeneratePassword generates a random password of length
func GeneratePassword(length int) ([]byte, error) {
	alphanumericBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	for i := range bytes {
		randInt, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumericBytes))))
		if err != nil {
			return bytes, errors.WithStack(err)
		}
		bytes[i] = alphanumericBytes[int(randInt.Int64())]
	}

	return bytes, nil
}
