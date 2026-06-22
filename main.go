package main

import (
	"fmt"
	"os"

	"github.com/ismailtrm/secaudit/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "secaudit:", err)
		os.Exit(1)
	}
}
