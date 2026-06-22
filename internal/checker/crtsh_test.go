package checker

import (
	"reflect"
	"testing"
)

func TestParseCrtSh(t *testing.T) {
	// Shape mirrors a real crt.sh response: name_value holds newline-separated
	// names, includes a "*." wildcard, a duplicate, and an unrelated domain.
	data := []byte(`[
		{"name_value":"hunerai.com\nwww.hunerai.com"},
		{"name_value":"*.hunerai.com"},
		{"name_value":"api.hunerai.com"},
		{"name_value":"other-domain.com"},
		{"name_value":"api.hunerai.com"}
	]`)

	got, err := parseCrtSh(data, "hunerai.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.hunerai.com", "hunerai.com", "www.hunerai.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCrtSh = %v, want %v", got, want)
	}
}

func TestParseCrtShBadJSON(t *testing.T) {
	if _, err := parseCrtSh([]byte("not json"), "x.com"); err == nil {
		t.Error("want error on invalid JSON")
	}
}
