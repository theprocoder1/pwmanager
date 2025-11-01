package main

import (
	"appliedcryptography-starter-kit/internal/pwmanager"
	"fmt"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

type GeneratorDialog struct {
	*walk.Dialog
	lengthSpinner     *walk.NumberEdit
	upperCheck        *walk.CheckBox
	lowerCheck        *walk.CheckBox
	numbersCheck      *walk.CheckBox
	symbolsCheck      *walk.CheckBox
	similarCheck      *walk.CheckBox
	ambiguousCheck    *walk.CheckBox
	passwordField     *walk.LineEdit
	strengthProgress  *walk.ProgressBar
	strengthLabel     *walk.TextLabel
	feedbackLabel     *walk.TextLabel
	generatedPassword string
}

func ShowPasswordGenerator(owner walk.Form) (string, error) {
	dlg := &GeneratorDialog{}

	var acceptPB, cancelPB *walk.PushButton

	if _, err := (Dialog{
		AssignTo:      &dlg.Dialog,
		Title:         "Password Generator",
		DefaultButton: &acceptPB,
		CancelButton:  &cancelPB,
		MinSize:       Size{Width: 400, Height: 500},
		Layout:        VBox{},
		Children: []Widget{
			GroupBox{
				Title:  "Options",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Length:"},
					NumberEdit{
						AssignTo: &dlg.lengthSpinner,
						Value:    12,
						MinValue: 4,
						MaxValue: 64,
						OnValueChanged: func() {
							dlg.generateAndUpdate()
						},
					},
					CheckBox{
						AssignTo: &dlg.upperCheck,
						Text:     "Uppercase (A-Z)",
						Checked:  true,
						OnCheckedChanged: func() {
							dlg.generateAndUpdate()
						},
					},
					CheckBox{
						AssignTo: &dlg.lowerCheck,
						Text:     "Lowercase (a-z)",
						Checked:  true,
						OnCheckedChanged: func() {
							dlg.generateAndUpdate()
						},
					},
					CheckBox{
						AssignTo: &dlg.numbersCheck,
						Text:     "Numbers (0-9)",
						Checked:  true,
						OnCheckedChanged: func() {
							dlg.generateAndUpdate()
						},
					},
					CheckBox{
						AssignTo: &dlg.symbolsCheck,
						Text:     "Symbols (!@#$...)",
						Checked:  true,
						OnCheckedChanged: func() {
							dlg.generateAndUpdate()
						},
					},
					CheckBox{
						AssignTo: &dlg.similarCheck,
						Text:     "Exclude Similar (l,1,I,o,0,O)",
						OnCheckedChanged: func() {
							dlg.generateAndUpdate()
						},
					},
					CheckBox{
						AssignTo: &dlg.ambiguousCheck,
						Text:     "Exclude Ambiguous ({,[,/,...)",
						OnCheckedChanged: func() {
							dlg.generateAndUpdate()
						},
					},
				},
			},
			GroupBox{
				Title:  "Generated Password",
				Layout: VBox{},
				Children: []Widget{
					LineEdit{
						AssignTo:  &dlg.passwordField,
						ReadOnly:  true,
						MinSize:   Size{Width: 300},
						TextColor: walk.RGB(0, 0, 0),
					},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							PushButton{
								Text: "🔄 Generate New",
								OnClicked: func() {
									dlg.generateAndUpdate()
								},
							},
							PushButton{
								Text: "📋 Copy",
								OnClicked: func() {
									if dlg.generatedPassword != "" {
										walk.Clipboard().SetText(dlg.generatedPassword)
									}
								},
							},
						},
					},
				},
			},
			GroupBox{
				Title:  "Password Strength",
				Layout: VBox{},
				Children: []Widget{
					ProgressBar{
						AssignTo: &dlg.strengthProgress,
						MinSize:  Size{Height: 20},
					},
					TextLabel{
						AssignTo:      &dlg.strengthLabel,
						TextAlignment: AlignHCenterVCenter,
					},
					TextLabel{
						AssignTo:      &dlg.feedbackLabel,
						TextAlignment: AlignHCenterVCenter,
						TextColor:     walk.RGB(100, 100, 100),
					},
				},
			},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &acceptPB,
						Text:     "Use Password",
						OnClicked: func() {
							dlg.Accept()
						},
					},
					PushButton{
						AssignTo:  &cancelPB,
						Text:      "Cancel",
						OnClicked: func() { dlg.Cancel() },
					},
				},
			},
		},
	}.Run(owner)); err != nil {
		return "", err
	}

	// Generate initial password
	dlg.generateAndUpdate()

	if dlg.Dialog.Result() == walk.DlgCmdOK {
		return dlg.generatedPassword, nil
	}

	return "", nil
}

func (dlg *GeneratorDialog) generateAndUpdate() {
	opts := pwmanager.PasswordOptions{
		Length:           int(dlg.lengthSpinner.Value()),
		IncludeUpper:     dlg.upperCheck.Checked(),
		IncludeLower:     dlg.lowerCheck.Checked(),
		IncludeNumbers:   dlg.numbersCheck.Checked(),
		IncludeSymbols:   dlg.symbolsCheck.Checked(),
		ExcludeSimilar:   dlg.similarCheck.Checked(),
		ExcludeAmbiguous: dlg.ambiguousCheck.Checked(),
	}

	// Generate new password
	password, err := pwmanager.GeneratePassword(opts)
	if err != nil || password == "" {
		dlg.passwordField.SetText("Invalid options selected")
		dlg.strengthProgress.SetValue(0)
		dlg.strengthLabel.SetText("N/A")
		dlg.feedbackLabel.SetText("Select at least one character type")
		return
	}

	// Store and display the password
	dlg.generatedPassword = password
	dlg.passwordField.SetText(password)

	// Update strength meter
	score, feedback := pwmanager.AnalyzePasswordStrength(password)
	dlg.strengthProgress.SetValue(score)

	// Set progress bar color based on score
	color := walk.RGB(200, 0, 0) // Default red
	switch {
	case score >= 80:
		color = walk.RGB(0, 160, 0) // Green
	case score >= 60:
		color = walk.RGB(200, 160, 0) // Yellow
	}

	brush, _ := walk.NewSolidColorBrush(color)
	dlg.strengthProgress.SetBackground(brush)

	dlg.strengthLabel.SetText(fmt.Sprintf("Strength: %d%%", score))
	if len(feedback) > 0 {
		dlg.feedbackLabel.SetText(feedback[len(feedback)-1])
	}
}
