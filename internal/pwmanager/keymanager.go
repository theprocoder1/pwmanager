package pwmanager

import (
	"appliedcryptography-starter-kit/internal/encrypt"
	"appliedcryptography-starter-kit/internal/hash"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const (
	masterKeySize = 32 // 256-bit master key
)

type keyManager struct {
	// The encrypted master key (AES-GCM)
	encryptedMKB64   string // base64(AES-GCM(MK))
	encryptedMKNonce string // base64(nonce)
}

// generateMasterKey creates a new random master key
func generateMasterKey() ([]byte, error) {
	mk := make([]byte, masterKeySize)
	if _, err := rand.Read(mk); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	return mk, nil
}

// wrapMasterKey encrypts the master key with a key derived from the password
func wrapMasterKey(masterKey []byte, password string, salt []byte) (*keyManager, error) {
	// Derive wrapping key from password using scrypt
	wrappingKey, err := deriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}

	// Generate nonce for master key encryption
	nonce, err := encrypt.GenerateNonce(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt master key
	encryptedMK, err := encrypt.EncryptAESGCM(wrappingKey, nonce, masterKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt master key: %w", err)
	}

	km := &keyManager{
		encryptedMKB64:   base64.StdEncoding.EncodeToString(encryptedMK),
		encryptedMKNonce: base64.StdEncoding.EncodeToString(nonce),
	}

	return km, nil
}

// unwrapMasterKey decrypts the master key using a key derived from the password
func (km *keyManager) unwrapMasterKey(password string, salt []byte) ([]byte, error) {
	// Derive wrapping key from password
	wrappingKey, err := deriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrapping key: %w", err)
	}

	// Decode encrypted master key and nonce
	encryptedMK, err := base64.StdEncoding.DecodeString(km.encryptedMKB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted master key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(km.encryptedMKNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decrypt master key
	masterKey, err := encrypt.DecryptAESGCM(wrappingKey, nonce, encryptedMK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %w", err)
	}

	return masterKey, nil
}

// deriveEntryKey derives a unique key for each entry using HKDF
func deriveEntryKey(masterKey []byte, entryID string) ([]byte, error) {
	return hash.HKDF(masterKey, []byte(entryID), []byte("entry-key"), 32)
}
