package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/huh/v2"

	"github.com/ismailtrm/secaudit/internal/checker"
	"github.com/ismailtrm/secaudit/internal/guard"
)

// WizardResult is the validated output of the interactive wizard.
type WizardResult struct {
	Domain    string
	Ownership checker.Ownership
	Mode      checker.Mode
}

// RunWizard collects and confirms scan parameters interactively. domain0 and the
// default ownership/mode prefill the form from CLI flags. The guardrail is
// enforced here, so an unauthorized active scan never reaches the engine.
func RunWizard(ctx context.Context, domain0, ownership0, mode0 string) (WizardResult, error) {
	domain := domain0
	ownership := ownership0
	mode := mode0

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Domain").
				Description("domain to scan, e.g. example.com").
				Value(&domain).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("required")
					}
					return nil
				}),
			huh.NewSelect[string]().Title("Ownership").
				Description("your relationship to this target").
				Options(
					huh.NewOption("I own / control it", "own"),
					huh.NewOption("Authorized (written permission)", "authorized"),
					huh.NewOption("Third party", "third-party"),
				).Value(&ownership),
			huh.NewSelect[string]().Title("Mode").
				Description("passive = read-only; active needs ownership/authorization").
				Options(
					huh.NewOption("Passive (safe, default)", "passive"),
					huh.NewOption("Active (own/authorized only)", "active"),
				).Value(&mode),
		),
	)
	if err := form.RunWithContext(ctx); err != nil {
		return WizardResult{}, err
	}

	owner, err := guard.ParseOwnership(ownership)
	if err != nil {
		return WizardResult{}, err
	}
	m, err := guard.ParseMode(mode)
	if err != nil {
		return WizardResult{}, err
	}
	if err := guard.Authorize(owner, m); err != nil {
		return WizardResult{}, err
	}
	return WizardResult{Domain: strings.TrimSpace(domain), Ownership: owner, Mode: m}, nil
}
