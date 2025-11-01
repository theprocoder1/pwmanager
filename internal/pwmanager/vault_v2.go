// appliedcryptography/internal/pwmanager/vault_v2.go
package pwmanager

import (
	"appliedcryptography-starter-kit/internal/encrypt"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

type VaultV2 struct {
	// KDF params for password-based key derivation
	KDF struct {
		N int `json:"N"`
		R int `json:"r"`
		P int `json:"p"`
		L int `json:"keyLen"`
	} `json:"kdf"`

	SaltB64 string                 `json:"salt"`       // base64(salt for password KDF)
	KeyMgr  keyManager             `json:"keyManager"` // Encrypted master key
	Entries map[string]CipherEntry `json:"entries"`    // id -> encrypted blob
	Version int                    `json:"version"`    // vault format version
}

// CreateV2 creates a new vault with a random master key
func CreateV2(masterPassword string) (*VaultV2, []byte, error) {
	// Generate salt for password-based key derivation
	salt, err := randomBytes(32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random master key
	masterKey, err := generateMasterKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Create key manager and wrap master key
	keyMgr, err := wrapMasterKey(masterKey, masterPassword, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap master key: %w", err)
	}

	v := &VaultV2{
		Entries: make(map[string]CipherEntry),
		KeyMgr:  *keyMgr,
		Version: 2,
	}
	v.KDF.N, v.KDF.R, v.KDF.P, v.KDF.L = kdfN, kdfr, kdfp, keyLen
	v.SaltB64 = base64.StdEncoding.EncodeToString(salt)

	return v, masterKey, nil
}

// UnlockV2 decrypts the master key using the provided password
func (v *VaultV2) UnlockV2(masterPassword string) ([]byte, error) {
	if v == nil {
		return nil, errors.New("nil vault")
	}

	salt, err := base64.StdEncoding.DecodeString(v.SaltB64)
	if err != nil {
		return nil, fmt.Errorf("bad salt: %w", err)
	}

	// Unwrap the master key using the password
	masterKey, err := v.KeyMgr.unwrapMasterKey(masterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap master key: %w", err)
	}

	return masterKey, nil
}

// ChangePasswordV2 re-wraps the master key with a new password
func (v *VaultV2) ChangePasswordV2(currentPassword, newPassword string) error {
	// First unlock with current password
	masterKey, err := v.UnlockV2(currentPassword)
	if err != nil {
		return fmt.Errorf("failed to unlock with current password: %w", err)
	}

	// Generate new salt
	salt, err := randomBytes(32)
	if err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	// Re-wrap master key with new password
	keyMgr, err := wrapMasterKey(masterKey, newPassword, salt)
	if err != nil {
		return fmt.Errorf("failed to wrap master key with new password: %w", err)
	}

	// Update vault
	v.SaltB64 = base64.StdEncoding.EncodeToString(salt)
	v.KeyMgr = *keyMgr

	return nil
}

// AddEntryV2 adds a new entry using a per-entry key derived from the master key
func (v *VaultV2) AddEntryV2(masterKey []byte, title, username, password, url, notes string) (string, error) {
	if v == nil {
		return "", errors.New("nil vault")
	}

	// Generate random ID for the entry
	idBytes, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	// Derive entry-specific key
	entryKey, err := deriveEntryKey(masterKey, id)
	if err != nil {
		return "", fmt.Errorf("failed to derive entry key: %w", err)
	}

	// Create and encrypt entry
	now := time.Now().UTC()
	plain := PlainEntry{
		Username:   username,
		Password:   password,
		URL:        url,
		Notes:      notes,
		CreatedAt:  now,
		ModifiedAt: now,
	}

	// Serialize entry data
	blob, err := json.Marshal(plain)
	if err != nil {
		return "", err
	}

	// Generate nonce and encrypt
	nonce, err := encrypt.GenerateNonce(12)
	if err != nil {
		return "", err
	}

	// Encrypt with entry-specific key
	ct, err := encrypt.EncryptAESGCM(entryKey, nonce, blob, []byte(id))
	if err != nil {
		return "", err
	}

	// Store entry
	v.Entries[id] = CipherEntry{
		ID:         id,
		Title:      title,
		NonceB64:   base64.StdEncoding.EncodeToString(nonce),
		CipherB64:  base64.StdEncoding.EncodeToString(ct),
		CreatedAt:  now,
		ModifiedAt: now,
	}

	return id, nil
}

// GetDecryptedV2 decrypts an entry using a derived key
func (v *VaultV2) GetDecryptedV2(masterKey []byte, id string) (*PlainEntry, *CipherEntry, error) {
	e, ok := v.Entries[id]
	if !ok {
		return nil, nil, errors.New("no such id")
	}

	// Derive entry-specific key
	entryKey, err := deriveEntryKey(masterKey, id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive entry key: %w", err)
	}

	// Decode nonce and ciphertext
	nonce, err := base64.StdEncoding.DecodeString(e.NonceB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bad nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(e.CipherB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ciphertext: %w", err)
	}

	// Decrypt with entry-specific key
	pt, err := encrypt.DecryptAESGCM(entryKey, nonce, ct, []byte(id))
	if err != nil {
		return nil, nil, err
	}

	var plain PlainEntry
	if err := json.Unmarshal(pt, &plain); err != nil {
		return nil, nil, err
	}

	return &plain, &e, nil
}

// SaveV2 saves the vault to disk
func (v *VaultV2) SaveV2(path string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadV2 loads a vault from disk
func LoadV2(path string) (*VaultV2, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var v VaultV2
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	if v.Version != 2 {
		return nil, fmt.Errorf("unsupported vault version: %d", v.Version)
	}

	if v.Entries == nil {
		v.Entries = make(map[string]CipherEntry)
	}

	return &v, nil
}
