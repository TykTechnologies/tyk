package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// trivial object schema used by the happy-path / error-path table.
const trivialSchema = `{
    "type": "object",
    "required": ["name"],
    "properties": {
        "name": {"type": "string"}
    }
}`

func TestDefaultValidator_TrivialSchema(t *testing.T) {
	v := DefaultValidator()
	cs, err := v.Compile(json.RawMessage(trivialSchema))
	if err != nil {
		t.Fatalf("compile trivial schema: %v", err)
	}

	tests := []struct {
		name        string
		instance    string
		wantErr     bool
		wantSubstrs []string // all must appear (case-insensitive) in error string
	}{
		{
			name:     "valid object",
			instance: `{"name":"alice"}`,
			wantErr:  false,
		},
		{
			name:        "wrong type for name",
			instance:    `{"name":42}`,
			wantErr:     true,
			wantSubstrs: []string{"name", "type"},
		},
		{
			name:        "missing required name",
			instance:    `{}`,
			wantErr:     true,
			wantSubstrs: []string{"name", "required"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := cs.Validate(json.RawMessage(tc.instance))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				lower := strings.ToLower(err.Error())
				for _, want := range tc.wantSubstrs {
					if !strings.Contains(lower, strings.ToLower(want)) {
						t.Errorf("error %q does not contain %q", err.Error(), want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestDefaultValidator_Draft2020Capability is the critical capability check:
// the chosen library must compile schemas that use 2020-12-only keywords.
// `prefixItems` was introduced in 2020-12 (replacing the tuple form of
// `items`). If the compiler defaulted to an older draft it would either
// silently ignore the keyword or fail validation against the meta-schema.
func TestDefaultValidator_Draft2020Capability(t *testing.T) {
	const schema2020 = `{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "array",
        "prefixItems": [
            {"type": "string"},
            {"type": "number"}
        ],
        "items": false
    }`

	v := DefaultValidator()
	cs, err := v.Compile(json.RawMessage(schema2020))
	if err != nil {
		t.Fatalf("compile 2020-12 schema with prefixItems: %v", err)
	}

	// Conforming tuple: [string, number] and no extra items.
	if err := cs.Validate(json.RawMessage(`["alice",42]`)); err != nil {
		t.Errorf("valid tuple rejected: %v", err)
	}

	// Non-conforming: extra item beyond prefixItems with items:false.
	if err := cs.Validate(json.RawMessage(`["alice",42,"extra"]`)); err == nil {
		t.Errorf("expected error for extra tuple item, got nil — prefixItems likely not enforced (wrong draft?)")
	}

	// Non-conforming: wrong type at position 1.
	if err := cs.Validate(json.RawMessage(`["alice","not-a-number"]`)); err == nil {
		t.Errorf("expected error for prefixItems type mismatch, got nil")
	}
}

func TestDefaultValidator_EmptySchema(t *testing.T) {
	v := DefaultValidator()
	if _, err := v.Compile(nil); err == nil {
		t.Errorf("expected error compiling nil schema")
	}
	if _, err := v.Compile(json.RawMessage("")); err == nil {
		t.Errorf("expected error compiling empty schema")
	}
}

func TestDefaultValidator_InvalidInstance(t *testing.T) {
	v := DefaultValidator()
	cs, err := v.Compile(json.RawMessage(trivialSchema))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := cs.Validate(json.RawMessage(`{not json`)); err == nil {
		t.Errorf("expected error for malformed JSON instance")
	}
}
