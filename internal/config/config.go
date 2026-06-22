// Package config resolves on-disk paths for secaudit (cache, future API keys).
package config

import (
	"os"
	"path/filepath"
)

const appName = "secaudit"

// Dir returns the per-user config directory (~/.config/secaudit on Linux),
// creating it if needed.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, appName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// CachePath returns the SQLite cache file path inside Dir.
func CachePath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cache.db"), nil
}
