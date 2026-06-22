package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
)

var sevColor = map[checker.Severity]color.Color{
	checker.SevCritical: lipgloss.Color("9"),   // red
	checker.SevHigh:     lipgloss.Color("202"), // orange
	checker.SevMedium:   lipgloss.Color("11"),  // yellow
	checker.SevLow:      lipgloss.Color("12"),  // blue
	checker.SevInfo:     lipgloss.Color("245"), // gray
}

var (
	faintStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	hintStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	scoreStyles = lipgloss.NewStyle().Bold(true)

	// launcher
	logoStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("13"))
	searchBox    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Foreground(lipgloss.Color("15")).Padding(0, 1)
	footerBar    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	chipSelected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("13")).Padding(0, 1)
	chipNormal   = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
)

var (
	borderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	titleStyle2 = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("13"))
	selectedBg  = lipgloss.Color("236")
	barFull     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	barEmpty    = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	keyStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))
)

// chip renders a labelled value, highlighted when selected.
func chip(label string, selected bool) string {
	if selected {
		return chipSelected.Render(label)
	}
	return chipNormal.Render(label)
}

func sevStyle(s checker.Severity) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(sevColor[s]).Bold(s >= checker.SevHigh)
}

// scoreColor picks a color for the health score.
func scoreColor(score int) color.Color {
	switch {
	case score >= 90:
		return lipgloss.Color("10")
	case score >= 70:
		return lipgloss.Color("11")
	default:
		return lipgloss.Color("9")
	}
}
