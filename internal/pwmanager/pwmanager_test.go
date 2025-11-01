package pwmanager

import (
	"os"
	"testing"
)

func TestVaultLifecycle(t *testing.T) {
	const testMaster = "testPassword123!"
	
	// Create new vault
	v, key, err := Create(testMaster)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if v == nil || key == nil {
		t.Fatal("Create() returned nil vault or key")
	}

	// Save to temporary file
	tmpFile := "test_vault.json"
	if err := v.Save(tmpFile); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	defer os.Remove(tmpFile)

	// Load vault
	v2, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Try to unlock with wrong password
	_, err = v2.Unlock("wrongpassword")
	if err == nil {
		t.Error("Unlock() with wrong password should fail")
	}

	// Unlock with correct password
	key2, err := v2.Unlock(testMaster)
	if err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}

	// Add an entry
	id, err := v2.AddEntry(key2, "Test Site", "testuser", "testpass", "https://test.com", "test notes")
	if err != nil {
		t.Fatalf("AddEntry() error = %v", err)
	}

	// List entries
	entries := v2.List()
	if len(entries) != 1 {
		t.Errorf("List() got %d entries, want 1", len(entries))
	}
	if entries[0].Title != "Test Site" {
		t.Errorf("List() entry title = %s, want Test Site", entries[0].Title)
	}

	// Search by title
	found := v2.SearchTitles("Test")
	if len(found) != 1 {
		t.Errorf("SearchTitles() got %d entries, want 1", len(found))
	}

	// Get decrypted entry
	plain, meta, err := v2.GetDecrypted(key2, id)
	if err != nil {
		t.Fatalf("GetDecrypted() error = %v", err)
	}
	if plain.Username != "testuser" || plain.Password != "testpass" {
		t.Error("GetDecrypted() returned wrong username/password")
	}
	if meta.Title != "Test Site" {
		t.Error("GetDecrypted() returned wrong title")
	}

	// Delete entry
	if !v2.Delete(id) {
		t.Error("Delete() failed")
	}
	if len(v2.List()) != 0 {
		t.Error("Delete() did not remove entry")
	}

	// Save changes
	if err := v2.Save(tmpFile); err != nil {
		t.Fatalf("Save() error after changes = %v", err)
	}
}