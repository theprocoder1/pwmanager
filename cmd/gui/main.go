// ================================================================
// Password Manager (GUI) — Core App (types, VM, bootstrap, handlers)
// Relies on:
//   - views.go    → showHomeView(), showMainView()  (declarative UI)
//   - handlers.go → onNewVault(), onOpenVault(), onAddEntry(), onDeleteEntry()
//   - pwmanager   → vault & crypto
// ================================================================

package main

import (
	"appliedcryptography-starter-kit/internal/pwmanager"
	"fmt"
	"strings"
	"time"

	"github.com/lxn/walk"
)

// -----------------------------
// 1) Types
// -----------------------------

// PasswordManagerWindow holds application state + UI handles.
type PasswordManagerWindow struct {
	// Core window
	*walk.MainWindow

	// Domain state
	vault     *pwmanager.Vault
	key       []byte
	file      string
	entries   []pwmanager.CipherEntry
	currentID string

	// View-model
	model *EntriesModel

	// UI elements - main
	table                *walk.ListBox // left list (titles)
	addAction            *walk.Action  // menu: Add
	editAction           *walk.Action  // menu: Edit
	deleteAction         *walk.Action  // menu: Delete
	themeAction          *walk.Action  // menu: Toggle theme
	changePasswordAction *walk.Action  // menu: Change password

	// UI elements - details panel
	titleLabel      *walk.TextLabel
	dateLabel       *walk.TextLabel
	usernameField   *walk.LineEdit
	passwordField   *walk.LineEdit
	urlField        *walk.LineEdit
	idField         *walk.LineEdit
	notesField      *walk.TextEdit
	copyUsernameBtn *walk.PushButton
	copyPasswordBtn *walk.PushButton
	copyUrlBtn      *walk.PushButton

	// UI state
	selectedIdx int
}

// EntriesModel backs the ListBox with titles.
type EntriesModel struct {
	walk.ListModelBase
	items []pwmanager.CipherEntry
}

// -----------------------------
// 2) View-model methods
// -----------------------------

func (m *EntriesModel) ItemCount() int          { return len(m.items) }
func (m *EntriesModel) Value(i int) interface{} { return m.items[i].Title }
func (m *EntriesModel) SetItems(items []pwmanager.CipherEntry) {
	m.items = items
	m.ListModelBase.PublishItemsReset()
}

// -----------------------------
// 3) App bootstrap
// -----------------------------

func main() {
	// Empty model & window defaults.
	model := &EntriesModel{items: make([]pwmanager.CipherEntry, 0)}

	mw := &PasswordManagerWindow{
		model:       model,
		selectedIdx: -1,
		entries:     make([]pwmanager.CipherEntry, 0),
		currentID:   "",
		file:        "",
	}

	// Panic guard → user-friendly message.
	defer func() {
		if r := recover(); r != nil {
			walk.MsgBox(nil, "Fatal Error",
				fmt.Sprintf("An unexpected error occurred: %v", r),
				walk.MsgBoxIconError)
		}
	}()

	// UI is created in views.go (declarative).
	mw.showHomeView()
	mw.Run()
}

// -----------------------------
// 4) Menu state & data refresh
// -----------------------------

// updateMenuItemsState enables/disables menu items based on vault/selection state.
func (mw *PasswordManagerWindow) updateMenuItemsState() {
	hasVault := mw.vault != nil && mw.key != nil

	if mw.addAction != nil {
		mw.addAction.SetEnabled(hasVault)
	}
	if mw.editAction != nil {
		mw.editAction.SetEnabled(hasVault && mw.currentID != "" && mw.selectedIdx >= 0)
	}
	if mw.deleteAction != nil {
		mw.deleteAction.SetEnabled(hasVault && mw.currentID != "" && mw.selectedIdx >= 0)
	}
	if mw.changePasswordAction != nil {
		mw.changePasswordAction.SetEnabled(hasVault)
	}
}

// refreshEntries reloads entries from the vault and updates the UI.
func (mw *PasswordManagerWindow) refreshEntries() {
	if mw.vault == nil || mw.key == nil {
		return
	}

	// Get current selection
	oldID := mw.currentID
	oldIdx := mw.selectedIdx

	// Update entries list
	mw.entries = mw.vault.List()
	mw.model.SetItems(mw.entries)

	// Try to restore selection if possible
	if oldID != "" && oldIdx >= 0 {
		// Look for the same entry ID in the new list
		for i, e := range mw.entries {
			if e.ID == oldID {
				mw.table.SetCurrentIndex(i)
				return
			}
		}
	}

	// If we couldn't restore selection, clear it
	mw.currentID = ""
	mw.selectedIdx = -1
	mw.clearDetailsFields()
	mw.updateMenuItemsState()
}

// -----------------------------
// 5) Selection handler
// -----------------------------

// onEntrySelected updates the details pane when the user selects an entry.
func (mw *PasswordManagerWindow) onEntrySelected() {
	if mw.table == nil {
		return
	}

	idx := mw.table.CurrentIndex()
	mw.clearDetailsFields()
	mw.currentID = ""
	mw.selectedIdx = -1

	// No selection / out of bounds
	if idx < 0 || idx >= len(mw.entries) {
		mw.updateMenuItemsState()
		return
	}

	entry := mw.entries[idx]
	mw.currentID = entry.ID
	mw.selectedIdx = idx
	mw.updateMenuItemsState()

	// Decrypt & render
	plain, _, err := mw.vault.GetDecrypted(mw.key, entry.ID)
	if err != nil {
		walk.MsgBox(mw, "Error", "Failed to decrypt entry: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	// Update all fields
	mw.titleLabel.SetText(entry.Title)
	mw.dateLabel.SetText("Last Modified: " + entry.ModifiedAt.Format("2006-01-02 15:04:05"))
	mw.usernameField.SetText(plain.Username)
	mw.passwordField.SetText(plain.Password)
	mw.urlField.SetText(plain.URL)
	mw.idField.SetText(entry.ID)
	mw.notesField.SetText(plain.Notes)

	// Setup copy buttons
	mw.copyUsernameBtn.SetEnabled(plain.Username != "")
	mw.copyPasswordBtn.SetEnabled(plain.Password != "")
	mw.copyUrlBtn.SetEnabled(plain.URL != "")
}

// secureClipboardCopy copies text to clipboard and schedules it to be cleared after delay
func (mw *PasswordManagerWindow) secureClipboardCopy(text string) {
	if text == "" {
		return
	}

	// Copy the text to clipboard
	walk.Clipboard().SetText(text)

	// Schedule clipboard clearing after 20 seconds
	go func() {
		time.Sleep(20 * time.Second)
		// Verify the clipboard still contains our text before clearing
		if current, _ := walk.Clipboard().Text(); current == text {
			mw.MainWindow.Synchronize(func() {
				walk.Clipboard().SetText("")
			})
		}
	}()
}

func (mw *PasswordManagerWindow) copyUsername() {
	if text := mw.usernameField.Text(); text != "" {
		mw.secureClipboardCopy(text)
	}
}

func (mw *PasswordManagerWindow) copyPassword() {
	if text := mw.passwordField.Text(); text != "" {
		mw.secureClipboardCopy(text)
	}
}

func (mw *PasswordManagerWindow) copyUrl() {
	if text := mw.urlField.Text(); text != "" {
		mw.secureClipboardCopy(text)
	}
}

// clearDetailsFields resets all detail fields to empty
func (mw *PasswordManagerWindow) clearDetailsFields() {
	mw.titleLabel.SetText("")
	mw.dateLabel.SetText("")
	mw.usernameField.SetText("")
	mw.passwordField.SetText("")
	mw.urlField.SetText("")
	mw.idField.SetText("")
	mw.notesField.SetText("")

	// Disable copy buttons
	mw.copyUsernameBtn.SetEnabled(false)
	mw.copyPasswordBtn.SetEnabled(false)
	mw.copyUrlBtn.SetEnabled(false)
}

// -----------------------------
// 6) Theme Management
// -----------------------------

func (mw *PasswordManagerWindow) toggleTheme() {
	if CurrentTheme == &LightTheme {
		CurrentTheme = &DarkTheme
	} else {
		CurrentTheme = &LightTheme
	}

	brush, _ := walk.NewSolidColorBrush(CurrentTheme.WindowBg)
	// Update main window
	mw.MainWindow.SetBackground(brush)

	// Update text colors
	if mw.titleLabel != nil {
		mw.titleLabel.SetTextColor(CurrentTheme.HeadingColor)
	}
	if mw.dateLabel != nil {
		mw.dateLabel.SetTextColor(CurrentTheme.SubtextColor)
	}

	// Update input fields
	if mw.notesField != nil {
		brush, _ := walk.NewSolidColorBrush(CurrentTheme.ControlBg)
		mw.notesField.SetBackground(brush)
	}

	// Update list box
	if mw.table != nil {
		brush, _ := walk.NewSolidColorBrush(CurrentTheme.ListBg)
		mw.table.SetBackground(brush)
	}

	// Update theme menu text
	if mw.themeAction != nil {
		if CurrentTheme == &LightTheme {
			mw.themeAction.SetText("Dark Theme")
		} else {
			mw.themeAction.SetText("Light Theme")
		}
	}
	fields := []*walk.LineEdit{
		mw.usernameField,
		mw.passwordField,
		mw.urlField,
		mw.idField,
	}

	inputBrush, _ := walk.NewSolidColorBrush(CurrentTheme.InputBg)
	for _, field := range fields {
		if field != nil {
			field.SetBackground(inputBrush)
			field.SetTextColor(CurrentTheme.InputText)
		}
	}

	// Update notes field
	if mw.notesField != nil {
		field := mw.notesField
		field.SetBackground(inputBrush)
		field.SetTextColor(CurrentTheme.InputText)
	}

	// Update list background
	if mw.table != nil {
		listBrush, _ := walk.NewSolidColorBrush(CurrentTheme.ListBg)
		mw.table.SetBackground(listBrush)
	}

	// Save theme preference (you might want to add a settings system later)
	mw.themeAction.SetText(CurrentTheme.Name + " Theme")

	// Force a redraw
	mw.MainWindow.Invalidate()
}

// -----------------------------
// 7) Helpers
// -----------------------------

// renderDetails formats a pretty details view in the right pane.
// (Use *pwmanager.PlainEntry — NOT a non-existent pwmanager.Details.)
func renderDetails(entry pwmanager.CipherEntry, details *pwmanager.PlainEntry) string {
	var b strings.Builder

	b.WriteString("════════════════════════════════════════════════════\n")
	b.WriteString(fmt.Sprintf("   📝 %s\n", entry.Title))
	b.WriteString("════════════════════════════════════════════════════\n\n")

	b.WriteString("🔑 CREDENTIALS\n")
	b.WriteString("────────────────\n")
	b.WriteString(fmt.Sprintf("   👤 Username:  %s\n", details.Username))
	b.WriteString(fmt.Sprintf("   🔒 Password:  %s\n", details.Password))
	b.WriteString("\n")

	b.WriteString("ℹ️  DETAILS\n")
	b.WriteString("────────────────\n")
	b.WriteString(fmt.Sprintf("   🏷️  ID:        %s\n", entry.ID))
	b.WriteString(fmt.Sprintf("   🕒 Modified:  %s\n", entry.ModifiedAt.Format("2006-01-02 15:04:05")))
	if details.URL != "" {
		b.WriteString(fmt.Sprintf("\n   🌐 URL:       %s\n", details.URL))
	}

	if details.Notes != "" {
		b.WriteString("\n📝 NOTES\n")
		b.WriteString("────────────────\n")
		for _, line := range strings.Split(details.Notes, "\n") {
			b.WriteString("   " + line + "\n")
		}
	}
	return b.String()
}
