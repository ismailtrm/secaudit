package cache

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCacheSetGetExpiry(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, ok := c.Get("missing"); ok {
		t.Error("expected miss for absent key")
	}

	if err := c.Set("k", []byte("v"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Get("k"); !ok || string(got) != "v" {
		t.Errorf("Get = %q, %v; want \"v\", true", got, ok)
	}

	// Already-expired entry is a miss.
	if err := c.Set("exp", []byte("old"), -time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("exp"); ok {
		t.Error("expected miss for expired key")
	}

	// Upsert overwrites.
	if err := c.Set("k", []byte("v2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Get("k"); string(got) != "v2" {
		t.Errorf("after upsert Get = %q; want \"v2\"", got)
	}
}
