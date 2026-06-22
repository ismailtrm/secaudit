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
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("13"))
	faintStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	hintStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	boxStyle    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	scoreStyles = lipgloss.NewStyle().Bold(true)
)

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
