package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ismailtrm/secaudit/cmd"
)

func main() {
	err := cmd.Execute()
	if err == nil {
		return
	}
	if errors.Is(err, cmd.ErrThresholdExceeded) {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "secaudit:", err)
	os.Exit(1)
}
