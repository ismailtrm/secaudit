// Package cache is a small SQLite-backed TTL cache for expensive passive
// lookups (e.g. crt.sh), so repeated scans of the same domain don't re-hit a
// flaky external service. It is best-effort: if the DB can't be opened, callers
// fall back to live queries.
package cache

import (
	"database/sql"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"

	"github.com/ismailtrm/secaudit/internal/config"
)

// Cache is a key/value store with per-entry expiry.
type Cache struct {
	db *sql.DB
}

// Open opens (creating if needed) the cache database at path.
func Open(path string) (*Cache, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// SQLite tolerates one writer at a time. Parallel checkers (crt.sh, wayback)
	// Set concurrently, so serialize on a single connection and wait on a busy DB
	// rather than dropping the write.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS entries (
		key        TEXT PRIMARY KEY,
		value      BLOB NOT NULL,
		expires_at INTEGER NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Cache{db: db}, nil
}

// Get returns the value for key if present and not expired.
func (c *Cache) Get(key string) ([]byte, bool) {
	var value []byte
	var exp int64
	err := c.db.QueryRow(`SELECT value, expires_at FROM entries WHERE key = ?`, key).Scan(&value, &exp)
	if err != nil {
		return nil, false
	}
	if time.Now().Unix() > exp {
		_, _ = c.db.Exec(`DELETE FROM entries WHERE key = ?`, key)
		return nil, false
	}
	return value, true
}

// Set stores value under key with the given time-to-live.
func (c *Cache) Set(key string, value []byte, ttl time.Duration) error {
	exp := time.Now().Add(ttl).Unix()
	_, err := c.db.Exec(
		`INSERT INTO entries (key, value, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`,
		key, value, exp)
	return err
}

// Close closes the underlying database.
func (c *Cache) Close() error { return c.db.Close() }

var (
	defaultOnce sync.Once
	defaultC    *Cache
)

// Default returns a process-wide cache opened at the configured path, or nil if
// it could not be opened (callers must nil-check and degrade gracefully).
func Default() *Cache {
	defaultOnce.Do(func() {
		path, err := config.CachePath()
		if err != nil {
			return
		}
		if c, err := Open(path); err == nil {
			defaultC = c
		}
	})
	return defaultC
}
