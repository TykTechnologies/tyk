package graphql

import (
	"encoding/json"
)

type Response struct {
	Errors Errors `json:"errors,omitempty"`
	// TODO: Data
	// TODO: Extensions
}

func (r Response) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
