package main

import (
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

// ThemeAwareBrush creates a SolidColorBrush for use in declarative UI
func ThemeAwareBrush(color walk.Color) Brush {
	return SolidColorBrush{Color: color}
}
