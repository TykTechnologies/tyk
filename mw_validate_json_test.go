package main

import (
	"encoding/base64"
	"testing"
)

var schema string = `{
    "title": "Person",
    "type": "object",
    "properties": {
        "firstName": {
            "type": "string"
        },
        "lastName": {
            "type": "string"
        },
        "age": {
            "description": "Age in years",
            "type": "integer",
            "minimum": 0
        }
    },
    "required": ["firstName", "lastName"]
}`

type out struct {
	Error string
	Code  int
}

func TestValidateSchema(t *testing.T) {
	want := []out{
		{"validation failed, server error", 400},
		{"payload validation failed: firstName: firstName is required: lastName: lastName is required", 400},
		{"payload validation failed: lastName: lastName is required", 400},
		{"", 200},
	}

	set := []string{
		``,
		`{}`,
		`{"firstName":"foo"}`,
		`{"firstName":"foo", "lastName":"foo"}`,
	}

	sch := base64.StdEncoding.EncodeToString([]byte(schema))
	for i, in := range set {
		e, code := validateJSONSchema(sch, in)
		if want[i].Error == "" {
			if e == nil && code != want[i].Code {
				t.Fatalf("Wanted nil error / %v, got %v / %v", want[i].Code, e, code)
			}
		} else {
			if e.Error() != want[i].Error || code != want[i].Code {
				t.Fatalf("Wanted: %v / %v, got %v / %v", want[i].Error, want[i].Code, e, code)
			}
		}

	}
}

// TODO Test with routes