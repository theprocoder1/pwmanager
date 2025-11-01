package main

import (
	"log"

	. "github.com/lxn/walk/declarative"
)

func (mw *PasswordManagerWindow) showMainView() {
	// Hide the old window if it exists (don't Dispose, which can end the Run loop)
	if mw.MainWindow != nil {
		mw.MainWindow.Hide()
	}

	// Create new main window
	if err := (MainWindow{
		AssignTo:   &mw.MainWindow,
		Title:      "Password Manager - Secure Vault",
		MinSize:    Size{Width: 1000, Height: 650},
		Size:       Size{Width: 1200, Height: 750},
		Background: ThemeAwareBrush(CurrentTheme.WindowBg),
		Layout:     VBox{MarginsZero: true},
		MenuItems: []MenuItem{
			Menu{
				Text: "&File",
				Items: []MenuItem{
					Action{
						Text:        "&New Vault...",
						OnTriggered: mw.onNewVault,
					},
					Action{
						Text:        "&Open Vault...",
						OnTriggered: mw.onOpenVault,
					},
					Action{
						AssignTo:    &mw.changePasswordAction,
						Text:        "&Change Password...",
						OnTriggered: mw.onChangePassword,
						Enabled:     false,
					},
					Separator{},
					Action{
						Text:        "&Delete Vault...",
						OnTriggered: mw.onDeleteVault,
					},
					Action{
						Text:        "Delete &All Vaults...",
						OnTriggered: mw.onDeleteAllVaults,
					},
					Separator{},
					Action{
						Text:        "E&xit",
						OnTriggered: func() { mw.Close() },
					},
					Separator{},
					Action{
						AssignTo:    &mw.themeAction,
						Text:        "Light Theme",
						OnTriggered: mw.toggleTheme,
					},
				},
			},
			Menu{
				Text: "&Edit",
				Items: []MenuItem{
					Action{
						AssignTo:    &mw.addAction,
						Text:        "Add Entry...",
						OnTriggered: mw.onAddEntry,
						Enabled:     false,
					},
					Action{
						AssignTo:    &mw.editAction,
						Text:        "Edit Entry...",
						OnTriggered: mw.onEditEntry,
						Enabled:     false,
					},
					Action{
						AssignTo:    &mw.deleteAction,
						Text:        "Delete Entry",
						OnTriggered: mw.onDeleteEntry,
						Enabled:     false,
					},
				},
			},
		},
		Children: []Widget{
			Composite{
				Layout: VBox{},
				Children: []Widget{
					HSplitter{
						Children: []Widget{
							// Left side - Enhanced list with better styling
							Composite{
								Layout: VBox{Margins: Margins{Left: 15, Top: 15, Right: 10, Bottom: 15}},
								Children: []Widget{
									// Vault Management Section
									Composite{
										Layout: VBox{},
										Children: []Widget{
											Label{
												Text:      "🔒 Vault Management",
												Font:      Font{Family: "Segoe UI", PointSize: 13, Bold: true},
												TextColor: CurrentTheme.HeadingColor,
											},
											VSpacer{Size: 2},
											Composite{
												Layout: HBox{},
												Children: []Widget{
													PushButton{
														Text:      "📂 New Vault...",
														OnClicked: mw.onNewVault,
														MinSize:   Size{Width: 120},
													},
													HSpacer{Size: 5},
													PushButton{
														Text:      "📂 Open Vault...",
														OnClicked: mw.onOpenVault,
														MinSize:   Size{Width: 120},
													},
												},
											},
											VSpacer{Size: 2},
											Composite{
												Layout: HBox{},
												Children: []Widget{
													PushButton{
														Text:      "❌ Delete Vault...",
														OnClicked: mw.onDeleteVault,
														MinSize:   Size{Width: 120},
													},
													HSpacer{Size: 5},
													PushButton{
														Text:      "❌ Delete All Vaults...",
														OnClicked: mw.onDeleteAllVaults,
														MinSize:   Size{Width: 120},
													},
												},
											},
										},
									},
									VSpacer{Size: 20},
									// Password Entries Section
									Composite{
										Layout: VBox{},
										Children: []Widget{
											Label{
												Text:      "📋 Password Entries",
												Font:      Font{Family: "Segoe UI", PointSize: 13, Bold: true},
												TextColor: CurrentTheme.HeadingColor,
											},
											VSpacer{Size: 2},
											Label{
												Text:      "Select an entry to view details",
												Font:      Font{Family: "Segoe UI", PointSize: 9},
												TextColor: CurrentTheme.SubtextColor,
											},
										},
									},
									VSpacer{Size: 10},
									ListBox{
										AssignTo:              &mw.table,
										Model:                 mw.model,
										OnCurrentIndexChanged: mw.onEntrySelected,
										MinSize:               Size{Width: 280, Height: 500},
										MaxSize:               Size{Width: 350},
										Font:                  Font{Family: "Segoe UI", PointSize: 11},
										Background:            ThemeAwareBrush(CurrentTheme.ListBg),
									},
								},
							},
							// Right side - Enhanced details panel
							Composite{
								Layout: VBox{Margins: Margins{Left: 10, Top: 15, Right: 15, Bottom: 15}},
								Children: []Widget{
									Composite{
										Layout: VBox{},
										Children: []Widget{
											Label{
												Text:      "🔐 Entry Details",
												Font:      Font{Family: "Segoe UI", PointSize: 13, Bold: true},
												TextColor: CurrentTheme.HeadingColor,
											},
											VSpacer{Size: 2},
											Label{
												Text:      "Secure credential information",
												Font:      Font{Family: "Segoe UI", PointSize: 9},
												TextColor: CurrentTheme.SubtextColor,
											},
										},
									},
									VSpacer{Size: 10},
									Composite{
										Layout: Grid{Columns: 1},
										Children: []Widget{
											Composite{
												Layout: VBox{},
												Children: []Widget{
													// Title Section
													GroupBox{
														Title:  "Entry Details",
														Layout: Grid{Columns: 1},
														Children: []Widget{
															TextLabel{AssignTo: &mw.titleLabel},
															TextLabel{AssignTo: &mw.dateLabel, Font: Font{PointSize: 9}},
														},
													},
													VSpacer{Size: 10},
													// Credentials Section
													GroupBox{
														Title:  "🔑 Credentials",
														Layout: Grid{Columns: 3, Spacing: 5},
														Children: []Widget{
															Label{Text: "Username:"},
															LineEdit{AssignTo: &mw.usernameField, ReadOnly: true},
															PushButton{AssignTo: &mw.copyUsernameBtn, Text: "📋 Copy", MaxSize: Size{Width: 70}, OnClicked: mw.copyUsername},
															Label{Text: "Password:"},
															LineEdit{AssignTo: &mw.passwordField, ReadOnly: true, PasswordMode: true},
															PushButton{AssignTo: &mw.copyPasswordBtn, Text: "📋 Copy", MaxSize: Size{Width: 70}, OnClicked: mw.copyPassword},
														},
													},
													VSpacer{Size: 10},
													// Additional Info Section
													GroupBox{
														Title:  "ℹ️ Additional Information",
														Layout: Grid{Columns: 3, Spacing: 5},
														Children: []Widget{
															Label{Text: "URL:"},
															LineEdit{AssignTo: &mw.urlField, ReadOnly: true},
															PushButton{AssignTo: &mw.copyUrlBtn, Text: "📋 Copy", MaxSize: Size{Width: 70}, OnClicked: mw.copyUrl},
															Label{Text: "ID:"},
															LineEdit{AssignTo: &mw.idField, ReadOnly: true},
															PushButton{Text: "📋 Copy", MaxSize: Size{Width: 70}, OnClicked: func() { mw.secureClipboardCopy(mw.idField.Text()) }},
														},
													},
													VSpacer{Size: 10},
													// Notes Section
													GroupBox{
														Title:  "📝 Notes",
														Layout: VBox{},
														Children: []Widget{
															TextEdit{
																AssignTo:   &mw.notesField,
																ReadOnly:   true,
																VScroll:    true,
																MinSize:    Size{Height: 100},
																Background: ThemeAwareBrush(CurrentTheme.ControlBg),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}.Create()); err != nil {
		log.Fatal(err)
	}

	mw.updateMenuItemsState()
}

func (mw *PasswordManagerWindow) showHomeView() {
	// Hide the old window if it exists (don't Dispose, which can end the Run loop)
	if mw.MainWindow != nil {
		mw.MainWindow.Hide()
	}

	// Create new home window
	if err := (MainWindow{
		AssignTo:   &mw.MainWindow,
		Title:      "Password Manager - Welcome",
		MinSize:    Size{Width: 600, Height: 400},
		Size:       Size{Width: 600, Height: 400},
		Background: ThemeAwareBrush(CurrentTheme.WindowBg),
		Layout:     VBox{MarginsZero: true},
		Children: []Widget{
			Composite{
				Layout: VBox{},
				Children: []Widget{
					VSpacer{Size: 40},
					TextLabel{
						Text:          "Secure Password Manager",
						Font:          Font{Family: "Segoe UI", PointSize: 24, Bold: true},
						TextColor:     CurrentTheme.HeadingColor,
						TextAlignment: AlignHCenterVCenter,
					},
					TextLabel{
						Text:          "Keep your passwords safe and organized",
						Font:          Font{Family: "Segoe UI", PointSize: 12},
						TextColor:     CurrentTheme.SubtextColor,
						TextAlignment: AlignHCenterVCenter,
					},
					VSpacer{Size: 60},
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							HSpacer{},
							PushButton{
								MinSize:   Size{Width: 200, Height: 50},
								Text:      "Create New Vault",
								Font:      Font{PointSize: 11},
								OnClicked: func() { mw.onNewVault() },
							},
							HSpacer{},
						},
					},
					VSpacer{Size: 20},
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							HSpacer{},
							PushButton{
								MinSize:   Size{Width: 200, Height: 50},
								Text:      "Open Existing Vault",
								Font:      Font{PointSize: 11},
								OnClicked: func() { mw.onOpenVault() },
							},
							HSpacer{},
						},
					},
					VSpacer{},
					TextLabel{
						Text:          "© 2025 Secure Password Manager",
						Font:          Font{Family: "Segoe UI", PointSize: 8},
						TextColor:     CurrentTheme.SubtextColor,
						TextAlignment: AlignHCenterVCenter,
					},
					VSpacer{Size: 10},
				},
			},
		},
	}.Create()); err != nil {
		log.Fatal(err)
	}

}
