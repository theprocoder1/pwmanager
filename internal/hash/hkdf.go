package hash

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF derives a key using HKDF-SHA256
func HKDF(masterKey, salt, info []byte, length int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, masterKey, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("failed to generate HKDF key: %w", err)
	}
	return key, nil
}
