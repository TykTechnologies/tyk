package jsonschema

import (
	"context"
	"encoding/json"

	jptr "github.com/qri-io/jsonpointer"
)

// If defines the if JSON Schema keyword
type If Schema

// NewIf allocates a new If keyword
func NewIf() Keyword {
	return &If{}
}

// Register implements the Keyword interface for If
func (f *If) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(f).Register(uri, registry)
}

// Resolve implements the Keyword interface for If
func (f *If) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for If
func (f *If) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[If] Validating")
	thenKW := currentState.Local.keywords["then"]
	elseKW := currentState.Local.keywords["else"]

	if thenKW == nil && elseKW == nil {
		// no then or else for if, aborting validation
		schemaDebug("[If] Aborting validation as no then or else is present")
		return
	}

	subState := currentState.NewSubState()
	subState.ClearState()
	subState.DescendBase("if")
	subState.DescendRelative("if")

	subState.Errs = &[]KeyError{}
	sch := Schema(*f)
	sch.ValidateKeyword(ctx, subState, data)

	currentState.Misc["ifResult"] = subState.IsValid()
}

// JSONProp implements the JSONPather for If
func (f If) JSONProp(name string) interface{} {
	return Schema(f).JSONProp(name)
}

// JSONChildren implements the JSONContainer interface for If
func (f If) JSONChildren() (res map[string]JSONPather) {
	return Schema(f).JSONChildren()
}

// UnmarshalJSON implements the json.Unmarshaler interface for If
func (f *If) UnmarshalJSON(data []byte) error {
	var sch Schema
	if err := json.Unmarshal(data, &sch); err != nil {
		return err
	}
	*f = If(sch)
	return nil
}

// MarshalJSON implements the json.Marshaler interface for If
func (f If) MarshalJSON() ([]byte, error) {
	return json.Marshal(Schema(f))
}

// Then defines the then JSON Schema keyword
type Then Schema

// NewThen allocates a new Then keyword
func NewThen() Keyword {
	return &Then{}
}

// Register implements the Keyword interface for Then
func (t *Then) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(t).Register(uri, registry)
}

// Resolve implements the Keyword interface for Then
func (t *Then) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(t).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for Then
func (t *Then) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Then] Validating")
	ifResult, okIf := currentState.Misc["ifResult"]
	if !okIf {
		schemaDebug("[Then] If result not found, skipping")
		// if not found
		return
	}
	if !(ifResult.(bool)) {
		schemaDebug("[Then] If result is false, skipping")
		// if was false
		return
	}

	subState := currentState.NewSubState()
	subState.DescendBase("then")
	subState.DescendRelative("then")

	sch := Schema(*t)
	sch.ValidateKeyword(ctx, subState, data)
	currentState.UpdateEvaluatedPropsAndItems(subState)
}

// JSONProp implements the JSONPather for Then
func (t Then) JSONProp(name string) interface{} {
	return Schema(t).JSONProp(name)
}

// JSONChildren implements the JSONContainer interface for Then
func (t Then) JSONChildren() (res map[string]JSONPather) {
	return Schema(t).JSONChildren()
}

// UnmarshalJSON implements the json.Unmarshaler interface for Then
func (t *Then) UnmarshalJSON(data []byte) error {
	var sch Schema
	if err := json.Unmarshal(data, &sch); err != nil {
		return err
	}
	*t = Then(sch)
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Then
func (t Then) MarshalJSON() ([]byte, error) {
	return json.Marshal(Schema(t))
}

// Else defines the else JSON Schema keyword
type Else Schema

// NewElse allocates a new Else keyword
func NewElse() Keyword {
	return &Else{}
}

// Register implements the Keyword interface for Else
func (e *Else) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(e).Register(uri, registry)
}

// Resolve implements the Keyword interface for Else
func (e *Else) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(e).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for Else
func (e *Else) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Else] Validating")
	ifResult, okIf := currentState.Misc["ifResult"]
	if !okIf {
		// if not found
		return
	}
	if ifResult.(bool) {
		// if was true
		return
	}

	subState := currentState.NewSubState()
	subState.DescendBase("else")
	subState.DescendRelative("else")

	sch := Schema(*e)
	sch.ValidateKeyword(ctx, subState, data)
}

// JSONProp implements the JSONPather for Else
func (e Else) JSONProp(name string) interface{} {
	return Schema(e).JSONProp(name)
}

// JSONChildren implements the JSONContainer interface for Else
func (e Else) JSONChildren() (res map[string]JSONPather) {
	return Schema(e).JSONChildren()
}

// UnmarshalJSON implements the json.Unmarshaler interface for Else
func (e *Else) UnmarshalJSON(data []byte) error {
	var sch Schema
	if err := json.Unmarshal(data, &sch); err != nil {
		return err
	}
	*e = Else(sch)
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Else
func (e Else) MarshalJSON() ([]byte, error) {
	return json.Marshal(Schema(e))
}
