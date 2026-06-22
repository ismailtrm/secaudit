package checker

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseWordlist(t *testing.T) {
	raw := "# header comment\nwww\n\n  api  \n# another\nmail\n\n"
	got := parseWordlist(raw)
	want := []string{"www", "api", "mail"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseWordlist = %v, want %v", got, want)
	}
}

func TestEmbeddedWordlistNonEmpty(t *testing.T) {
	if n := len(parseWordlist(wordlistRaw)); n < 50 {
		t.Errorf("embedded wordlist has %d labels, expected a substantial list", n)
	}
}

func TestWaybackUnmarshal(t *testing.T) {
	data := []byte(`{"url":"hunerai.com","archived_snapshots":{"closest":{` +
		`"status":"200","available":true,` +
		`"url":"http://web.archive.org/web/20251108092652/https://www.hunerai.com/",` +
		`"timestamp":"20251108092652"}}}`)
	var wr waybackResp
	if err := json.Unmarshal(data, &wr); err != nil {
		t.Fatal(err)
	}
	c := wr.ArchivedSnapshots.Closest
	if !c.Available || c.Timestamp != "20251108092652" || c.URL == "" {
		t.Errorf("unexpected parse: %+v", c)
	}
}
