// appliedcryptography/internal/pwmanager/pwmanager.go
package pwmanager

import (
	"appliedcryptography-starter-kit/internal/encrypt"
	"appliedcryptography-starter-kit/internal/hash"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	kdfN      = 32768 // scrypt N
	kdfr      = 8
	kdfp      = 1
	keyLen    = 32 // AES-256
	verifyMsg = "vault-check"
)

// ---------- types saved to disk (JSON) ----------

type Vault struct {
	// KDF params are included so you can change them in future versions without breaking old vaults.
	KDF struct {
		N int `json:"N"`
		R int `json:"r"`
		P int `json:"p"`
		L int `json:"keyLen"`
	} `json:"kdf"`

	SaltB64   string                 `json:"salt"`         // base64(salt)
	KeyMgr    keyManager             `json:"keyManager"`   // Encrypted master key
	VerifyNnc string                 `json:"verify_nonce"` // base64(nonce)
	VerifyCt  string                 `json:"verify_ct"`    // base64(AES-GCM(verifyMsg))
	Entries   map[string]CipherEntry `json:"entries"`      // id -> encrypted blob
}

type CipherEntry struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`      // kept in clear so you can list/search
	NonceB64   string    `json:"nonce"`      // base64(12B nonce)
	CipherB64  string    `json:"ciphertext"` // base64(GCM(PlainEntry JSON))
	CreatedAt  time.Time `json:"createdAt"`
	ModifiedAt time.Time `json:"modifiedAt"`
}

// This is never written as a top-level record; it’s encrypted as JSON into CipherEntry.CipherB64
type PlainEntry struct {
	Username   string    `json:"username"`
	Password   string    `json:"password"`
	URL        string    `json:"url,omitempty"`
	Notes      string    `json:"notes,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	ModifiedAt time.Time `json:"modifiedAt"`
}

// ---------- helpers ----------

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func deriveKey(masterPassword string, salt []byte) ([]byte, error) {
	return hash.Scrypt([]byte(masterPassword), salt, kdfN, kdfr, kdfp, keyLen)
}

// ---------- Vault lifecycle ----------

// Create a brand new empty vault and return it + the master key.
func Create(masterPassword string) (*Vault, []byte, error) {
	// Generate random salt and derive key for password verification
	salt, err := randomBytes(32)
	if err != nil {
		return nil, nil, err
	}
	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return nil, nil, err
	}

	// Create empty vault
	v := &Vault{
		Entries: make(map[string]CipherEntry),
	}
	v.KDF.N, v.KDF.R, v.KDF.P, v.KDF.L = kdfN, kdfr, kdfp, keyLen
	v.SaltB64 = base64.StdEncoding.EncodeToString(salt)

	// Generate and wrap master key
	masterKey, err := generateMasterKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	km, err := wrapMasterKey(masterKey, masterPassword, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap master key: %w", err)
	}
	v.KeyMgr = *km

	// Create verification block
	nonce, err := encrypt.GenerateNonce(12)
	if err != nil {
		return nil, nil, err
	}
	ct, err := encrypt.EncryptAESGCM(key, nonce, []byte(verifyMsg), nil)
	if err != nil {
		return nil, nil, err
	}
	v.VerifyNnc = base64.StdEncoding.EncodeToString(nonce)
	v.VerifyCt = base64.StdEncoding.EncodeToString(ct)

	return v, masterKey, nil
}

// CreateWithExistingKey creates a new vault using an existing master key.
// This is used for changing the password without re-encrypting all entries.
func CreateWithExistingKey(masterPassword string, masterKey []byte) (*Vault, error) {
	// Generate random salt and derive key for password verification
	salt, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Create empty vault
	v := &Vault{
		Entries: make(map[string]CipherEntry),
	}
	v.KDF.N, v.KDF.R, v.KDF.P, v.KDF.L = kdfN, kdfr, kdfp, keyLen
	v.SaltB64 = base64.StdEncoding.EncodeToString(salt)

	// Wrap the existing master key with the new password
	km, err := wrapMasterKey(masterKey, masterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap master key: %w", err)
	}
	v.KeyMgr = *km

	// Create verification block
	nonce, err := encrypt.GenerateNonce(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ct, err := encrypt.EncryptAESGCM(key, nonce, []byte(verifyMsg), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification block: %w", err)
	}
	v.VerifyNnc = base64.StdEncoding.EncodeToString(nonce)
	v.VerifyCt = base64.StdEncoding.EncodeToString(ct)

	return v, nil
}

// Unlock derives the key from the provided password and verifies it against the stored check.
// Returns the unwrapped master key if successful.
func (v *Vault) Unlock(masterPassword string) ([]byte, error) {
	if v == nil {
		return nil, errors.New("nil vault")
	}
	salt, err := base64.StdEncoding.DecodeString(v.SaltB64)
	if err != nil {
		return nil, fmt.Errorf("bad salt: %w", err)
	}
	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(v.VerifyNnc)
	if err != nil {
		return nil, fmt.Errorf("bad verify nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(v.VerifyCt)
	if err != nil {
		return nil, fmt.Errorf("bad verify ct: %w", err)
	}
	pt, err := encrypt.DecryptAESGCM(key, nonce, ct, nil)
	if err != nil || string(pt) != verifyMsg {
		return nil, errors.New("wrong master password")
	}

	// Unwrap the master key
	masterKey, err := v.KeyMgr.unwrapMasterKey(masterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap master key: %w", err)
	}

	return masterKey, nil
}

// Save to path
func (v *Vault) Save(path string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Load from path
func Load(path string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	if v.Entries == nil {
		v.Entries = make(map[string]CipherEntry)
	}
	return &v, nil
}

// ---------- CRUD operations ----------

func (v *Vault) AddEntry(key []byte, title, username, password, url, notes string) (string, error) {
	if v == nil {
		return "", errors.New("nil vault")
	}
	idBytes, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	now := time.Now().UTC()
	plain := PlainEntry{
		Username:   username,
		Password:   password,
		URL:        url,
		Notes:      notes,
		CreatedAt:  now,
		ModifiedAt: now,
	}
	blob, err := json.Marshal(plain)
	if err != nil {
		return "", err
	}

	nonce, err := encrypt.GenerateNonce(12)
	if err != nil {
		return "", err
	}

	// Derive a unique key for this entry
	entryKey, err := deriveEntryKey(key, id)
	if err != nil {
		return "", fmt.Errorf("failed to derive entry key: %w", err)
	}

	aad := []byte(id) // bind ct to entry id
	ct, err := encrypt.EncryptAESGCM(entryKey, nonce, blob, aad)
	if err != nil {
		return "", err
	}

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

func (v *Vault) List() []CipherEntry {
	out := make([]CipherEntry, 0, len(v.Entries))
	for _, e := range v.Entries {
		out = append(out, e)
	}
	return out
}

func (v *Vault) GetDecrypted(key []byte, id string) (*PlainEntry, *CipherEntry, error) {
	e, ok := v.Entries[id]
	if !ok {
		return nil, nil, errors.New("no such id")
	}
	nonce, err := base64.StdEncoding.DecodeString(e.NonceB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bad nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(e.CipherB64)
	if err != nil {
		return nil, nil, fmt.Errorf("bad ciphertext: %w", err)
	}

	// Derive the unique key for this entry
	entryKey, err := deriveEntryKey(key, id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive entry key: %w", err)
	}

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

func (v *Vault) UpdateEntry(key []byte, id string, title, username, password, url, notes *string) error {
	plain, meta, err := v.GetDecrypted(key, id)
	if err != nil {
		return err
	}

	// apply changes if non-nil
	if title != nil {
		meta.Title = *title
	}
	if username != nil {
		plain.Username = *username
	}
	if password != nil {
		plain.Password = *password
	}
	if url != nil {
		plain.URL = *url
	}
	if notes != nil {
		plain.Notes = *notes
	}
	now := time.Now().UTC()
	plain.ModifiedAt = now
	meta.ModifiedAt = now

	blob, err := json.Marshal(plain)
	if err != nil {
		return err
	}
	nonce, err := encrypt.GenerateNonce(12)
	if err != nil {
		return err
	}

	// Derive the unique key for this entry
	entryKey, err := deriveEntryKey(key, id)
	if err != nil {
		return fmt.Errorf("failed to derive entry key: %w", err)
	}

	ct, err := encrypt.EncryptAESGCM(entryKey, nonce, blob, []byte(id))
	if err != nil {
		return err
	}

	meta.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
	meta.CipherB64 = base64.StdEncoding.EncodeToString(ct)
	v.Entries[id] = *meta
	return nil
}

func (v *Vault) Delete(id string) bool {
	if _, ok := v.Entries[id]; !ok {
		return false
	}
	delete(v.Entries, id)
	return true
}

// SearchTitles returns entries whose Title contains query (case-insensitive).
func (v *Vault) SearchTitles(query string) []CipherEntry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	out := make([]CipherEntry, 0, len(v.Entries))
	for _, e := range v.Entries {
		if strings.Contains(strings.ToLower(e.Title), q) {
			out = append(out, e)
		}
	}
	// sort by ModifiedAt desc for nicer UX
	sort.Slice(out, func(i, j int) bool { return out[i].ModifiedAt.After(out[j].ModifiedAt) })
	return out
}

// FindByExactTitle returns entries whose Title equals the provided title (case-insensitive).
func (v *Vault) FindByExactTitle(title string) []CipherEntry {
	t := strings.ToLower(strings.TrimSpace(title))
	if t == "" {
		return nil
	}
	out := make([]CipherEntry, 0, 1)
	for _, e := range v.Entries {
		if strings.ToLower(e.Title) == t {
			out = append(out, e)
		}
	}
	// deterministic order
	sort.Slice(out, func(i, j int) bool { return out[i].ModifiedAt.After(out[j].ModifiedAt) })
	return out
}
