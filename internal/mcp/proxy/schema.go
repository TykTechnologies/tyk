// Package proxy implements the MCP-Proxy middleware: it converts an
// OAS-3.1-derived MCP tool catalogue into HTTP requests against the upstream
// API, and validates JSON-RPC tool-call arguments against each tool's
// InputSchema (JSON Schema 2020-12).
//
// This file isolates the JSON-Schema-2020-12 instance validator behind a small
// interface so the concrete library can be swapped at GA without touching
// call sites. The current backing implementation is
// github.com/santhosh-tekuri/jsonschema/v5 (Apache-2.0), which is already an
// indirect dependency of Tyk and is the library named in
// RFC-API-TO-MCP-V7 §7 / §16 step 5.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

// Validator compiles a raw JSON Schema 2020-12 document into a CompiledSchema
// that can validate JSON instances. Implementations must be safe for
// concurrent use after Compile() returns.
type Validator interface {
	Compile(rawSchema json.RawMessage) (CompiledSchema, error)
}

// CompiledSchema validates a single JSON instance against a previously
// compiled schema. Implementations must be safe for concurrent use.
type CompiledSchema interface {
	// Validate returns nil if instance conforms to the schema. Otherwise it
	// returns an error whose string surfaces the failed keyword (e.g.
	// "required", "type") and the JSON pointer to the offending location.
	Validate(instance json.RawMessage) error
}

// DefaultValidator returns the default Validator backed by
// santhosh-tekuri/jsonschema/v5 pinned to Draft 2020-12.
func DefaultValidator() Validator {
	return santhoshValidator{}
}

// santhoshValidator is the unexported concrete implementation. It holds no
// state — each Compile() call uses a fresh *jsonschema.Compiler so that
// resource registrations do not leak between tools.
type santhoshValidator struct{}

// schemaURL is the in-memory URL under which we register each tool's
// InputSchema with the compiler. It is never resolved over the network.
const schemaURL = "mem://input-schema.json"

func (santhoshValidator) Compile(rawSchema json.RawMessage) (CompiledSchema, error) {
	if len(rawSchema) == 0 {
		return nil, fmt.Errorf("proxy: empty JSON schema")
	}
	c := jsonschema.NewCompiler()
	// Pin to Draft 2020-12 — OAS 3.1 InputSchemas are 2020-12 instances.
	c.Draft = jsonschema.Draft2020
	if err := c.AddResource(schemaURL, bytes.NewReader(rawSchema)); err != nil {
		return nil, fmt.Errorf("proxy: add schema resource: %w", err)
	}
	s, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: compile schema: %w", err)
	}
	return &santhoshCompiled{schema: s}, nil
}

type santhoshCompiled struct {
	schema *jsonschema.Schema
}

func (sc *santhoshCompiled) Validate(instance json.RawMessage) error {
	// santhosh-tekuri/jsonschema operates on already-decoded Go values
	// (map[string]interface{}, []interface{}, etc.), so unmarshal first.
	var v interface{}
	if err := json.Unmarshal(instance, &v); err != nil {
		return fmt.Errorf("proxy: invalid JSON instance: %w", err)
	}
	if err := sc.schema.Validate(v); err != nil {
		// The library's *ValidationError.Error() string already contains
		// the failed keyword and JSON pointer; surface it verbatim.
		return err
	}
	return nil
}
