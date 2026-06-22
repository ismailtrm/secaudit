package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ismailtrm/secaudit/internal/checker"
)

var checkersCmd = &cobra.Command{
	Use:   "checkers",
	Short: "Inspect registered checkers",
}

var checkersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all checkers and their availability",
	RunE:  runCheckersList,
}

func init() {
	checkersCmd.AddCommand(checkersListCmd)
}

func runCheckersList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	fmt.Printf("%-18s %-8s %-9s %s\n", "ID", "MODE", "CATEGORY", "STATUS")
	for _, c := range checker.All() {
		status := "available"
		if ok, reason := c.Available(ctx); !ok {
			status = "unavailable: " + reason
		}
		fmt.Printf("%-18s %-8s %-9s %s\n", c.ID(), c.Mode(), c.Category(), status)
	}
	return nil
}
