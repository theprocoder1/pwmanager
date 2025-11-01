package main

import (
	"appliedcryptography-starter-kit/internal/pwmanager"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func defaultVaultDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(cfgDir) == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", fmt.Errorf("cannot determine a config/home directory: %v / %v", err, herr)
		}
		cfgDir = filepath.Join(home, ".config")
	}

	appDir := filepath.Join(cfgDir, "SecurePasswordManager")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create app dir: %w", err)
	}
	return appDir, nil
}

func vaultPathForName(name string) (string, error) {
	dir, err := defaultVaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".json"), nil
}

func listVaults() ([]string, error) {
	dir, err := defaultVaultDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var vaults []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			vaults = append(vaults, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return vaults, nil
}

func (mw *PasswordManagerWindow) onNewVault() {
	var dlg *walk.Dialog
	var vaultNameLE, masterLE, confirmLE *walk.LineEdit
	var dlgResult int
	var dlgErr error
	var vaultName, masterPwd, confirmPwd string

	dlgResult, dlgErr = Dialog{
		AssignTo: &dlg,
		Title:    "Create New Vault",
		MinSize:  Size{Width: 300, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "Vault name (e.g. work, personal):"},
			LineEdit{AssignTo: &vaultNameLE},
			Label{Text: "Enter Master Password:"},
			LineEdit{AssignTo: &masterLE, PasswordMode: true},
			Label{Text: "Confirm Master Password:"},
			LineEdit{AssignTo: &confirmLE, PasswordMode: true},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Create",
						OnClicked: func() {
							name := strings.TrimSpace(vaultNameLE.Text())
							m := strings.TrimSpace(masterLE.Text())
							c := strings.TrimSpace(confirmLE.Text())
							if name == "" {
								walk.MsgBox(dlg, "Error", "Vault name is required", walk.MsgBoxIconError)
								return
							}
							if m == "" || len(m) < 8 {
								walk.MsgBox(dlg, "Error", "Password must be at least 8 characters", walk.MsgBoxIconError)
								return
							}
							if m != c {
								walk.MsgBox(dlg, "Error", "Passwords don't match", walk.MsgBoxIconError)
								return
							}
							vaultName = name
							masterPwd = m
							confirmPwd = c
							dlg.Accept()
						},
					},
					PushButton{
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(mw)

	if dlgErr != nil || dlgResult != walk.DlgCmdOK {
		return
	}
	if masterPwd != confirmPwd {
		walk.MsgBox(mw, "Error", "Passwords don't match", walk.MsgBoxIconError)
		return
	}

	// Build vault path
	path, err := vaultPathForName(vaultName)
	if err != nil {
		walk.MsgBox(mw, "Error", "Failed to resolve vault path: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	if _, err := os.Stat(path); err == nil {
		if walk.MsgBox(mw, "Warning", "Vault already exists. Overwrite?", walk.MsgBoxIconWarning|walk.MsgBoxYesNo) != walk.DlgCmdYes {
			return
		}
	}

	// Create vault
	v, key, err := pwmanager.Create(masterPwd)
	if err != nil {
		walk.MsgBox(mw, "Error", "Failed to create vault: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	if err := v.Save(path); err != nil {
		walk.MsgBox(mw, "Error", "Failed to save vault: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	mw.vault = v
	mw.key = key
	mw.file = path
	mw.refreshEntries()
	mw.updateMenuItemsState()
	mw.showMainView()
}

func (mw *PasswordManagerWindow) onChangePassword() {
	if mw.vault == nil {
		return
	}

	var oldPassword, newPassword *walk.LineEdit
	var dlg *walk.Dialog

	Dialog{
		AssignTo: &dlg,
		Title:    "Change Vault Password",
		MinSize:  Size{Width: 300, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "Current Password:"},
			LineEdit{AssignTo: &oldPassword, PasswordMode: true},
			Label{Text: "New Password:"},
			LineEdit{AssignTo: &newPassword, PasswordMode: true},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Change",
						OnClicked: func() {
							oldPw := oldPassword.Text()
							newPw := newPassword.Text()

							if newPw == "" {
								walk.MsgBox(mw, "Error", "New password cannot be empty", walk.MsgBoxIconError)
								return
							}

							// Verify the old password first
							_, err := mw.vault.Unlock(oldPw)
							if err != nil {
								walk.MsgBox(mw, "Error", "Current password is incorrect", walk.MsgBoxIconError)
								return
							}

							// Create a new vault with the new password, but keep the same master key
							newVault, err := pwmanager.CreateWithExistingKey(newPw, mw.key)
							if err != nil {
								walk.MsgBox(mw, "Error", "Failed to create new vault: "+err.Error(), walk.MsgBoxIconError)
								return
							}

							// Copy over all entries
							newVault.Entries = mw.vault.Entries

							// Update vault in memory
							mw.vault = newVault

							// Save the vault
							if err := mw.vault.Save(mw.file); err != nil {
								walk.MsgBox(mw, "Error", "Failed to save vault: "+err.Error(), walk.MsgBoxIconError)
								return
							}

							// Refresh the entries display
							mw.refreshEntries()

							dlg.Accept()
							walk.MsgBox(mw, "Success", "Password changed successfully", walk.MsgBoxIconInformation)
						},
					},
					PushButton{
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(mw)
}

func (mw *PasswordManagerWindow) onOpenVault() {
	vaults, err := listVaults()
	if err != nil {
		walk.MsgBox(mw, "Error", "Failed to list vaults: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	if len(vaults) == 0 {
		if walk.MsgBox(mw, "No Vaults", "No vaults found. Create a new one?", walk.MsgBoxIconInformation|walk.MsgBoxYesNo) == walk.DlgCmdYes {
			mw.onNewVault()
		}
		return
	}

	var selectedVault string
	var dlg *walk.Dialog
	var lb *walk.ListBox
	var dlgResult int

	dlgResult, _ = Dialog{
		AssignTo: &dlg,
		Title:    "Select Vault",
		MinSize:  Size{Width: 250, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "Choose a vault to open:"},
			ListBox{
				AssignTo:              &lb,
				Model:                 vaults,
				OnCurrentIndexChanged: func() { selectedVault = vaults[lb.CurrentIndex()] },
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Open",
						OnClicked: func() {
							if selectedVault == "" && len(vaults) > 0 {
								selectedVault = vaults[0]
							}
							dlg.Accept()
						},
					},
					PushButton{
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(mw)

	if dlgResult != walk.DlgCmdOK || selectedVault == "" {
		return
	}

	path, err := vaultPathForName(selectedVault)
	if err != nil {
		walk.MsgBox(mw, "Error", "Failed to resolve vault path: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	v, err := pwmanager.Load(path)
	if err != nil || v == nil {
		walk.MsgBox(mw, "Error", "Failed to load vault: "+fmt.Sprint(err), walk.MsgBoxIconError)
		return
	}

	var pwDlg *walk.Dialog
	var masterLE *walk.LineEdit
	var masterPwd string

	_, _ = Dialog{
		AssignTo: &pwDlg,
		Title:    "Unlock Vault",
		MinSize:  Size{Width: 300, Height: 150},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "Enter Master Password:"},
			LineEdit{AssignTo: &masterLE, PasswordMode: true},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Unlock",
						OnClicked: func() {
							m := strings.TrimSpace(masterLE.Text())
							if m == "" {
								walk.MsgBox(pwDlg, "Error", "Password required", walk.MsgBoxIconError)
								return
							}
							masterPwd = m
							pwDlg.Accept()
						},
					},
					PushButton{
						Text:      "Cancel",
						OnClicked: func() { pwDlg.Cancel() },
					},
				},
			},
		},
	}.Run(mw)

	key, err := v.Unlock(masterPwd)
	if err != nil || key == nil {
		walk.MsgBox(mw, "Error", "Failed to unlock vault: incorrect password", walk.MsgBoxIconError)
		return
	}

	mw.key = key
	mw.vault = v
	mw.file = path
	mw.entries = v.List()
	if mw.model == nil {
		mw.model = new(EntriesModel)
	}
	mw.showMainView()
	mw.refreshEntries()
	mw.updateMenuItemsState()
}

func (mw *PasswordManagerWindow) onAddEntry() {
	var d *walk.Dialog
	var acceptPB, cancelPB *walk.PushButton
	var titleLE, usernameLE, passwordLE, urlLE *walk.LineEdit
	var notesTE *walk.TextEdit
	var dlgResult int
	var dlgErr error
	var titleStr, usernameStr, passwordStr, urlStr, notesStr string

	dlgResult, dlgErr = Dialog{
		AssignTo:      &d,
		Title:         "Add Entry",
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 300, Height: 300},
		Layout:        VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Title:"},
					LineEdit{AssignTo: &titleLE},
					Label{Text: "Username:"},
					LineEdit{AssignTo: &usernameLE},
					Label{Text: "Password:"},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							LineEdit{AssignTo: &passwordLE, PasswordMode: true},
							PushButton{
								Text: "🎲 Generate",
								OnClicked: func() {
									if pw, err := ShowPasswordGenerator(d); err == nil && pw != "" {
										passwordLE.SetText(pw)
									}
								},
							},
						},
					},
					Label{Text: "URL:"},
					LineEdit{AssignTo: &urlLE},
				},
			},
			Label{Text: "Notes:"},
			TextEdit{AssignTo: &notesTE},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						AssignTo: &acceptPB,
						Text:     "OK",
						OnClicked: func() {
							title := strings.TrimSpace(titleLE.Text())
							if title == "" {
								walk.MsgBox(d, "Error", "Title is required", walk.MsgBoxIconError)
								return
							}
							titleStr = title
							usernameStr = usernameLE.Text()
							passwordStr = passwordLE.Text()
							urlStr = urlLE.Text()
							notesStr = notesTE.Text()
							d.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "Cancel",
						OnClicked: func() { d.Cancel() },
					},
				},
			},
		},
	}.Run(mw)

	if dlgErr != nil {
		walk.MsgBox(mw, "Error", dlgErr.Error(), walk.MsgBoxIconError)
		return
	}
	if dlgResult != walk.DlgCmdOK {
		return
	}

	if _, err := mw.vault.AddEntry(mw.key, titleStr, usernameStr, passwordStr, urlStr, notesStr); err != nil {
		walk.MsgBox(mw, "Error", "Failed to add entry: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	if err := mw.vault.Save(mw.file); err != nil {
		walk.MsgBox(mw, "Error", "Failed to save vault: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	mw.refreshEntries()
}

func (mw *PasswordManagerWindow) onEditEntry() {
	if mw.vault == nil || mw.key == nil || mw.currentID == "" {
		walk.MsgBox(mw, "Error", "Please select an entry to edit", walk.MsgBoxIconError)
		return
	}
	if mw.selectedIdx < 0 || mw.selectedIdx >= len(mw.entries) {
		walk.MsgBox(mw, "Error", "Invalid selection", walk.MsgBoxIconError)
		return
	}

	entry := mw.entries[mw.selectedIdx]
	if entry.ID != mw.currentID {
		walk.MsgBox(mw, "Error", "Selection mismatch", walk.MsgBoxIconError)
		return
	}

	// Get the current entry details
	plain, _, err := mw.vault.GetDecrypted(mw.key, entry.ID)
	if err != nil {
		walk.MsgBox(mw, "Error", "Failed to decrypt entry: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	var d *walk.Dialog
	var acceptPB, cancelPB *walk.PushButton
	var titleLE, usernameLE, passwordLE, urlLE *walk.LineEdit
	var notesTE *walk.TextEdit
	var dlgResult int
	var dlgErr error
	var titleStr, usernameStr, passwordStr, urlStr, notesStr string

	dlgResult, dlgErr = Dialog{
		AssignTo:      &d,
		Title:         "Edit Entry",
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 300, Height: 300},
		Layout:        VBox{},
		Children: []Widget{
			Composite{
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Title:"},
					LineEdit{AssignTo: &titleLE, Text: entry.Title},
					Label{Text: "Username:"},
					LineEdit{AssignTo: &usernameLE, Text: plain.Username},
					Label{Text: "Password:"},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							LineEdit{AssignTo: &passwordLE, Text: plain.Password, PasswordMode: true},
							PushButton{
								Text: "🎲 Generate",
								OnClicked: func() {
									if pw, err := ShowPasswordGenerator(d); err == nil && pw != "" {
										passwordLE.SetText(pw)
									}
								},
							},
						},
					},
					Label{Text: "URL:"},
					LineEdit{AssignTo: &urlLE, Text: plain.URL},
				},
			},
			Label{Text: "Notes:"},
			TextEdit{AssignTo: &notesTE, Text: plain.Notes},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						AssignTo: &acceptPB,
						Text:     "Save",
						OnClicked: func() {
							title := strings.TrimSpace(titleLE.Text())
							if title == "" {
								walk.MsgBox(d, "Error", "Title is required", walk.MsgBoxIconError)
								return
							}
							titleStr = title
							usernameStr = usernameLE.Text()
							passwordStr = passwordLE.Text()
							urlStr = urlLE.Text()
							notesStr = notesTE.Text()
							d.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "Cancel",
						OnClicked: func() { d.Cancel() },
					},
				},
			},
		},
	}.Run(mw)

	if dlgErr != nil {
		walk.MsgBox(mw, "Error", dlgErr.Error(), walk.MsgBoxIconError)
		return
	}
	if dlgResult != walk.DlgCmdOK {
		return
	}

	// Delete the old entry and add the new one
	ok := mw.vault.Delete(entry.ID)
	if !ok {
		walk.MsgBox(mw, "Error", "Failed to update the entry (not found)", walk.MsgBoxIconError)
		return
	}

	// Add the new entry
	if _, err := mw.vault.AddEntry(mw.key, titleStr, usernameStr, passwordStr, urlStr, notesStr); err != nil {
		walk.MsgBox(mw, "Error", "Failed to update entry: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	if err := mw.vault.Save(mw.file); err != nil {
		walk.MsgBox(mw, "Error", "Failed to save changes: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	mw.refreshEntries()
}

func deleteVault(name string) error {
	path, err := vaultPathForName(name)
	if err != nil {
		return fmt.Errorf("failed to get vault path: %w", err)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete vault %s: %w", name, err)
	}
	return nil
}

func (mw *PasswordManagerWindow) onDeleteVault() {
	vaults, err := listVaults()
	if err != nil {
		walk.MsgBox(mw, "Error", "Failed to list vaults: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	if len(vaults) == 0 {
		walk.MsgBox(mw, "No Vaults", "No vaults found to delete.", walk.MsgBoxIconInformation)
		return
	}

	var selectedVault string
	var dlg *walk.Dialog
	var lb *walk.ListBox
	var dlgResult int

	dlgResult, _ = Dialog{
		AssignTo: &dlg,
		Title:    "Select Vault to Delete",
		MinSize:  Size{Width: 250, Height: 200},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: "Choose a vault to delete:"},
			ListBox{
				AssignTo:              &lb,
				Model:                 vaults,
				OnCurrentIndexChanged: func() { selectedVault = vaults[lb.CurrentIndex()] },
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						Text: "Delete",
						OnClicked: func() {
							if selectedVault == "" && len(vaults) > 0 {
								selectedVault = vaults[0]
							}
							dlg.Accept()
						},
					},
					PushButton{
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(mw)

	if dlgResult != walk.DlgCmdOK || selectedVault == "" {
		return
	}

	// Extra confirmation for deletion
	if walk.MsgBox(mw, "Confirm Delete", fmt.Sprintf("Are you sure you want to delete vault '%s'? This cannot be undone.", selectedVault),
		walk.MsgBoxIconWarning|walk.MsgBoxYesNo) != walk.DlgCmdYes {
		return
	}

	if err := deleteVault(selectedVault); err != nil {
		walk.MsgBox(mw, "Error", "Failed to delete vault: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	// If we deleted the currently open vault, clear it//
	if mw.vault != nil {
		if currentPath, err := vaultPathForName(selectedVault); err == nil && currentPath == mw.file {
			mw.vault = nil
			mw.key = nil
			mw.file = ""
			mw.entries = nil
			mw.currentID = ""
			mw.selectedIdx = -1
			mw.clearDetailsFields()
			mw.refreshEntries()
			mw.updateMenuItemsState()
			if mw.MainWindow != nil {
				mw.MainWindow.Hide()
			}
		}
	}

	walk.MsgBox(mw, "Success", fmt.Sprintf("Vault '%s' has been deleted", selectedVault), walk.MsgBoxIconInformation)
}

func deleteAllVaults() error {
	dir, err := defaultVaultDir()
	if err != nil {
		return fmt.Errorf("failed to get vault directory: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read vault directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			path := filepath.Join(dir, entry.Name())
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to delete vault %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

func (mw *PasswordManagerWindow) onDeleteAllVaults() {
	if walk.MsgBox(mw, "Confirm Delete All", "Are you sure you want to delete ALL vaults? This cannot be undone.",
		walk.MsgBoxIconWarning|walk.MsgBoxYesNo) != walk.DlgCmdYes {
		return
	}

	if err := deleteAllVaults(); err != nil {
		walk.MsgBox(mw, "Error", "Failed to delete vaults: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	walk.MsgBox(mw, "Success", "All vaults have been deleted", walk.MsgBoxIconInformation)

	// Clear current vault and UI
	mw.vault = nil
	mw.key = nil
	mw.file = ""
	mw.entries = nil
	mw.currentID = ""
	mw.selectedIdx = -1
	mw.clearDetailsFields()
	mw.refreshEntries()
	mw.updateMenuItemsState()
	if mw.MainWindow != nil {
		mw.MainWindow.Hide()
	}
}

func (mw *PasswordManagerWindow) onDeleteEntry() {
	if mw.vault == nil || mw.key == nil || mw.currentID == "" {
		walk.MsgBox(mw, "Error", "Please select an entry to delete", walk.MsgBoxIconError)
		return
	}
	if mw.selectedIdx < 0 || mw.selectedIdx >= len(mw.entries) {
		walk.MsgBox(mw, "Error", "Invalid selection", walk.MsgBoxIconError)
		return
	}

	entry := mw.entries[mw.selectedIdx]
	if entry.ID != mw.currentID {
		walk.MsgBox(mw, "Error", "Selection mismatch", walk.MsgBoxIconError)
		return
	}

	if walk.MsgBox(mw, "Confirm Delete", "Are you sure you want to delete '"+entry.Title+"'?",
		walk.MsgBoxIconQuestion|walk.MsgBoxOKCancel) != walk.DlgCmdOK {
		return
	}

	// Remember the current index
	currentIdx := mw.selectedIdx

	// Delete the entry
	ok := mw.vault.Delete(mw.currentID)
	if !ok {
		walk.MsgBox(mw, "Error", "Failed to delete the entry (not found)", walk.MsgBoxIconError)
		return
	}

	// Save the vault
	if err := mw.vault.Save(mw.file); err != nil {
		walk.MsgBox(mw, "Error", "Failed to save vault: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	// Refresh entries and update selection
	mw.refreshEntries()

	// Select the next item if available
	if currentIdx >= len(mw.entries) {
		currentIdx = len(mw.entries) - 1
	}
	if currentIdx >= 0 && len(mw.entries) > 0 {
		mw.table.SetCurrentIndex(currentIdx)
	}
	mw.selectedIdx = -1
	mw.clearDetailsFields()
	mw.refreshEntries()
}
