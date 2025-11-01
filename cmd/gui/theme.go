package main

import (
	"github.com/lxn/walk"
)

// Theme defines colors for the application
type Theme struct {
	Name string

	// Background colors
	WindowBg   walk.Color
	ControlBg  walk.Color
	ListBg     walk.Color
	GroupBoxBg walk.Color

	// Text colors
	TextColor    walk.Color
	HeadingColor walk.Color
	SubtextColor walk.Color
	LinkColor    walk.Color

	// Border and separator colors
	BorderColor    walk.Color
	SeparatorColor walk.Color

	// UI element colors
	ButtonBg   walk.Color
	ButtonText walk.Color
	InputBg    walk.Color
	InputText  walk.Color
}

var (
	LightTheme = Theme{
		Name:           "Light",
		WindowBg:       walk.RGB(248, 250, 252), // Light gray
		ControlBg:      walk.RGB(255, 255, 255), // White
		ListBg:         walk.RGB(252, 253, 254), // Very light gray
		GroupBoxBg:     walk.RGB(255, 255, 255), // White
		TextColor:      walk.RGB(31, 41, 55),    // Dark gray
		HeadingColor:   walk.RGB(55, 65, 81),    // Medium gray
		SubtextColor:   walk.RGB(107, 114, 128), // Light gray
		LinkColor:      walk.RGB(59, 130, 246),  // Blue
		BorderColor:    walk.RGB(229, 231, 235), // Light gray
		SeparatorColor: walk.RGB(229, 231, 235), // Light gray
		ButtonBg:       walk.RGB(255, 255, 255), // White
		ButtonText:     walk.RGB(31, 41, 55),    // Dark gray
		InputBg:        walk.RGB(255, 255, 255), // White
		InputText:      walk.RGB(31, 41, 55),    // Dark gray
	}

	DarkTheme = Theme{
		Name:           "Dark",
		WindowBg:       walk.RGB(17, 24, 39),    // Very dark blue
		ControlBg:      walk.RGB(31, 41, 55),    // Dark blue gray
		ListBg:         walk.RGB(24, 31, 45),    // Dark blue
		GroupBoxBg:     walk.RGB(31, 41, 55),    // Dark blue gray
		TextColor:      walk.RGB(243, 244, 246), // Very light gray
		HeadingColor:   walk.RGB(229, 231, 235), // Light gray
		SubtextColor:   walk.RGB(156, 163, 175), // Medium gray
		LinkColor:      walk.RGB(96, 165, 250),  // Light blue
		BorderColor:    walk.RGB(55, 65, 81),    // Medium gray
		SeparatorColor: walk.RGB(55, 65, 81),    // Medium gray
		ButtonBg:       walk.RGB(55, 65, 81),    // Medium gray
		ButtonText:     walk.RGB(243, 244, 246), // Very light gray
		InputBg:        walk.RGB(17, 24, 39),    // Very dark blue
		InputText:      walk.RGB(243, 244, 246), // Very light gray
	}
)

// CurrentTheme holds the active theme
var CurrentTheme = &LightTheme
