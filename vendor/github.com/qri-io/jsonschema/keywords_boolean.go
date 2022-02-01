package jsonschema

import (
	"context"
	"encoding/json"
	"strconv"

	jptr "github.com/qri-io/jsonpointer"
)

// AllOf defines the allOf JSON Schema keyword
type AllOf []*Schema

// NewAllOf allocates a new AllOf keyword
func NewAllOf() Keyword {
	return &AllOf{}
}

// Register implements the Keyword interface for AllOf
func (a *AllOf) Register(uri string, registry *SchemaRegistry) {
	for _, sch := range *a {
		sch.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for AllOf
func (a *AllOf) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer == nil {
		return nil
	}
	current := pointer.Head()
	if current == nil {
		return nil
	}

	pos, err := strconv.Atoi(*current)
	if err != nil {
		return nil
	}

	if pos < 0 || pos >= len(*a) {
		return nil
	}

	return (*a)[pos].Resolve(pointer.Tail(), uri)

	return nil
}

// ValidateKeyword implements the Keyword interface for AllOf
func (a *AllOf) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[AllOf] Validating")
	stateCopy := currentState.NewSubState()
	stateCopy.ClearState()
	invalid := false
	for i, sch := range *a {
		subState := currentState.NewSubState()
		subState.ClearState()
		subState.DescendBase("allOf", strconv.Itoa(i))
		subState.DescendRelative("allOf", strconv.Itoa(i))
		subState.Errs = &[]KeyError{}
		sch.ValidateKeyword(ctx, subState, data)
		currentState.AddSubErrors(*subState.Errs...)
		stateCopy.UpdateEvaluatedPropsAndItems(subState)
		if !subState.IsValid() {
			invalid = true
		}
	}
	if !invalid {
		currentState.UpdateEvaluatedPropsAndItems(stateCopy)
	}
}

// JSONProp implements the JSONPather for AllOf
func (a AllOf) JSONProp(name string) interface{} {
	idx, err := strconv.Atoi(name)
	if err != nil {
		return nil
	}
	if idx > len(a) || idx < 0 {
		return nil
	}
	return a[idx]
}

// JSONChildren implements the JSONContainer interface for AllOf
func (a AllOf) JSONChildren() (res map[string]JSONPather) {
	res = map[string]JSONPather{}
	for i, sch := range a {
		res[strconv.Itoa(i)] = sch
	}
	return
}

// AnyOf defines the anyOf JSON Schema keyword
type AnyOf []*Schema

// NewAnyOf allocates a new AnyOf keyword
func NewAnyOf() Keyword {
	return &AnyOf{}
}

// Register implements the Keyword interface for AnyOf
func (a *AnyOf) Register(uri string, registry *SchemaRegistry) {
	for _, sch := range *a {
		sch.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for AnyOf
func (a *AnyOf) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer == nil {
		return nil
	}
	current := pointer.Head()
	if current == nil {
		return nil
	}

	pos, err := strconv.Atoi(*current)
	if err != nil {
		return nil
	}

	if pos < 0 || pos >= len(*a) {
		return nil
	}

	return (*a)[pos].Resolve(pointer.Tail(), uri)

	return nil
}

// ValidateKeyword implements the Keyword interface for AnyOf
func (a *AnyOf) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[AnyOf] Validating")
	for i, sch := range *a {
		subState := currentState.NewSubState()
		subState.ClearState()
		subState.DescendBase("anyOf", strconv.Itoa(i))
		subState.DescendRelative("anyOf", strconv.Itoa(i))
		subState.Errs = &[]KeyError{}
		sch.ValidateKeyword(ctx, subState, data)
		if subState.IsValid() {
			currentState.UpdateEvaluatedPropsAndItems(subState)
			return
		}
	}

	currentState.AddError(data, "did Not match any specified AnyOf schemas")
}

// JSONProp implements the JSONPather for AnyOf
func (a AnyOf) JSONProp(name string) interface{} {
	idx, err := strconv.Atoi(name)
	if err != nil {
		return nil
	}
	if idx > len(a) || idx < 0 {
		return nil
	}
	return a[idx]
}

// JSONChildren implements the JSONContainer interface for AnyOf
func (a AnyOf) JSONChildren() (res map[string]JSONPather) {
	res = map[string]JSONPather{}
	for i, sch := range a {
		res[strconv.Itoa(i)] = sch
	}
	return
}

// OneOf defines the oneOf JSON Schema keyword
type OneOf []*Schema

// NewOneOf allocates a new OneOf keyword
func NewOneOf() Keyword {
	return &OneOf{}
}

// Register implements the Keyword interface for OneOf
func (o *OneOf) Register(uri string, registry *SchemaRegistry) {
	for _, sch := range *o {
		sch.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for OneOf
func (o *OneOf) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer == nil {
		return nil
	}
	current := pointer.Head()
	if current == nil {
		return nil
	}

	pos, err := strconv.Atoi(*current)
	if err != nil {
		return nil
	}

	if pos < 0 || pos >= len(*o) {
		return nil
	}

	return (*o)[pos].Resolve(pointer.Tail(), uri)

	return nil
}

// ValidateKeyword implements the Keyword interface for OneOf
func (o *OneOf) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[OneOf] Validating")
	matched := false
	stateCopy := currentState.NewSubState()
	stateCopy.ClearState()
	for i, sch := range *o {
		subState := currentState.NewSubState()
		subState.ClearState()
		subState.DescendBase("oneOf", strconv.Itoa(i))
		subState.DescendRelative("oneOf", strconv.Itoa(i))
		subState.Errs = &[]KeyError{}
		sch.ValidateKeyword(ctx, subState, data)
		stateCopy.UpdateEvaluatedPropsAndItems(subState)
		if subState.IsValid() {
			if matched {
				currentState.AddError(data, "matched more than one specified OneOf schemas")
				return
			}
			matched = true
		}
	}
	if !matched {
		currentState.AddError(data, "did not match any of the specified OneOf schemas")
	} else {
		currentState.UpdateEvaluatedPropsAndItems(stateCopy)
	}
}

// JSONProp implements the JSONPather for OneOf
func (o OneOf) JSONProp(name string) interface{} {
	idx, err := strconv.Atoi(name)
	if err != nil {
		return nil
	}
	if idx > len(o) || idx < 0 {
		return nil
	}
	return o[idx]
}

// JSONChildren implements the JSONContainer interface for OneOf
func (o OneOf) JSONChildren() (res map[string]JSONPather) {
	res = map[string]JSONPather{}
	for i, sch := range o {
		res[strconv.Itoa(i)] = sch
	}
	return
}

// Not defines the not JSON Schema keyword
type Not Schema

// NewNot allocates a new Not keyword
func NewNot() Keyword {
	return &Not{}
}

// Register implements the Keyword interface for Not
func (n *Not) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(n).Register(uri, registry)
}

// Resolve implements the Keyword interface for Not
func (n *Not) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(n).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for Not
func (n *Not) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Not] Validating")
	subState := currentState.NewSubState()
	subState.DescendBase("not")
	subState.DescendRelative("not")

	subState.Errs = &[]KeyError{}
	sch := Schema(*n)
	sch.ValidateKeyword(ctx, subState, data)
	if subState.IsValid() {
		currentState.AddError(data, "result was valid, ('not') expected invalid")
	}
}

// JSONProp implements the JSONPather for Not
func (n Not) JSONProp(name string) interface{} {
	return Schema(n).JSONProp(name)
}

// JSONChildren implements the JSONContainer interface for Not
func (n Not) JSONChildren() (res map[string]JSONPather) {
	return Schema(n).JSONChildren()
}

// UnmarshalJSON implements the json.Unmarshaler interface for Not
func (n *Not) UnmarshalJSON(data []byte) error {
	var sch Schema
	if err := json.Unmarshal(data, &sch); err != nil {
		return err
	}
	*n = Not(sch)
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Not
func (n Not) MarshalJSON() ([]byte, error) {
	return json.Marshal(Schema(n))
}
