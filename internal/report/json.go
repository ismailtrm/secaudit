package report

import "encoding/json"

// JSON renders the report as indented JSON for scripting/CI.
func (r Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
