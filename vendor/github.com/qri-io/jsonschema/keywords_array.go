package jsonschema

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"

	jptr "github.com/qri-io/jsonpointer"
)

// Items defines the items JSON Schema keyword
type Items struct {
	single  bool
	Schemas []*Schema
}

// NewItems allocates a new Items keyword
func NewItems() Keyword {
	return &Items{}
}

// Register implements the Keyword interface for Items
func (it *Items) Register(uri string, registry *SchemaRegistry) {
	for _, v := range it.Schemas {
		v.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for Items
func (it *Items) Resolve(pointer jptr.Pointer, uri string) *Schema {
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

	if pos < 0 || pos >= len(it.Schemas) {
		return nil
	}

	return it.Schemas[pos].Resolve(pointer.Tail(), uri)

	return nil
}

// ValidateKeyword implements the Keyword interface for Items
func (it Items) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Items] Validating")
	if arr, ok := data.([]interface{}); ok {
		if it.single {
			subState := currentState.NewSubState()
			subState.DescendBase("items")
			subState.DescendRelative("items")
			for i, elem := range arr {
				subState.ClearState()
				subState.DescendInstanceFromState(currentState, strconv.Itoa(i))
				it.Schemas[0].ValidateKeyword(ctx, subState, elem)
				subState.SetEvaluatedIndex(i)
				// TODO(arqu): this might clash with additional/unevaluated
				// Properties/Items, should separate out
				currentState.UpdateEvaluatedPropsAndItems(subState)
			}
		} else {
			subState := currentState.NewSubState()
			subState.DescendBase("items")
			for i, vs := range it.Schemas {
				if i < len(arr) {
					subState.ClearState()
					subState.DescendRelativeFromState(currentState, "items", strconv.Itoa(i))
					subState.DescendInstanceFromState(currentState, strconv.Itoa(i))

					vs.ValidateKeyword(ctx, subState, arr[i])
					subState.SetEvaluatedIndex(i)
					currentState.UpdateEvaluatedPropsAndItems(subState)
				}
			}
		}
	}
}

// JSONProp implements the JSONPather for Items
func (it Items) JSONProp(name string) interface{} {
	idx, err := strconv.Atoi(name)
	if err != nil {
		return nil
	}
	if idx > len(it.Schemas) || idx < 0 {
		return nil
	}
	return it.Schemas[idx]
}

// JSONChildren implements the JSONContainer interface for Items
func (it Items) JSONChildren() (res map[string]JSONPather) {
	res = map[string]JSONPather{}
	for i, sch := range it.Schemas {
		res[strconv.Itoa(i)] = sch
	}
	return
}

// UnmarshalJSON implements the json.Unmarshaler interface for Items
func (it *Items) UnmarshalJSON(data []byte) error {
	s := &Schema{}
	if err := json.Unmarshal(data, s); err == nil {
		*it = Items{single: true, Schemas: []*Schema{s}}
		return nil
	}
	ss := []*Schema{}
	if err := json.Unmarshal(data, &ss); err != nil {
		return err
	}
	*it = Items{Schemas: ss}
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Items
func (it Items) MarshalJSON() ([]byte, error) {
	if it.single {
		return json.Marshal(it.Schemas[0])
	}
	return json.Marshal([]*Schema(it.Schemas))
}

// MaxItems defines the maxItems JSON Schema keyword
type MaxItems int

// NewMaxItems allocates a new MaxItems keyword
func NewMaxItems() Keyword {
	return new(MaxItems)
}

// Register implements the Keyword interface for MaxItems
func (m *MaxItems) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MaxItems
func (m *MaxItems) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MaxItems
func (m MaxItems) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MaxItems] Validating")
	if arr, ok := data.([]interface{}); ok {
		if len(arr) > int(m) {
			currentState.AddError(data, fmt.Sprintf("array length %d exceeds %d max", len(arr), m))
			return
		}
	}
}

// MinItems defines the minItems JSON Schema keyword
type MinItems int

// NewMinItems allocates a new MinItems keyword
func NewMinItems() Keyword {
	return new(MinItems)
}

// Register implements the Keyword interface for MinItems
func (m *MinItems) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MinItems
func (m *MinItems) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MinItems
func (m MinItems) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MinItems] Validating")
	if arr, ok := data.([]interface{}); ok {
		if len(arr) < int(m) {
			currentState.AddError(data, fmt.Sprintf("array length %d below %d minimum items", len(arr), m))
			return
		}
	}
}

// UniqueItems defines the uniqueItems JSON Schema keyword
type UniqueItems bool

// NewUniqueItems allocates a new UniqueItems keyword
func NewUniqueItems() Keyword {
	return new(UniqueItems)
}

// Register implements the Keyword interface for UniqueItems
func (u *UniqueItems) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for UniqueItems
func (u *UniqueItems) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for UniqueItems
func (u UniqueItems) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[UniqueItems] Validating")
	if arr, ok := data.([]interface{}); ok {
		found := []interface{}{}
		for _, elem := range arr {
			for _, f := range found {
				if reflect.DeepEqual(f, elem) {
					currentState.AddError(data, fmt.Sprintf("array items must be unique. duplicated entry: %v", elem))
					return
				}
			}
			found = append(found, elem)
		}
	}
}

// Contains defines the contains JSON Schema keyword
type Contains Schema

// NewContains allocates a new Contains keyword
func NewContains() Keyword {
	return &Contains{}
}

// Register implements the Keyword interface for Contains
func (c *Contains) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(c).Register(uri, registry)
}

// Resolve implements the Keyword interface for Contains
func (c *Contains) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(c).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for Contains
func (c *Contains) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Contains] Validating")
	v := Schema(*c)
	if arr, ok := data.([]interface{}); ok {
		valid := false
		matchCount := 0
		subState := currentState.NewSubState()
		subState.ClearState()
		subState.DescendBase("contains")
		subState.DescendRelative("contains")
		for i, elem := range arr {
			subState.ClearState()
			subState.DescendInstanceFromState(currentState, strconv.Itoa(i))
			subState.Errs = &[]KeyError{}
			v.ValidateKeyword(ctx, subState, elem)
			if subState.IsValid() {
				valid = true
				matchCount++
			}
		}
		if valid {
			currentState.Misc["containsCount"] = matchCount
		} else {
			currentState.AddError(data, fmt.Sprintf("must contain at least one of: %v", c))
		}
	}
}

// JSONProp implements the JSONPather for Contains
func (c Contains) JSONProp(name string) interface{} {
	return Schema(c).JSONProp(name)
}

// JSONChildren implements the JSONContainer interface for Contains
func (c Contains) JSONChildren() (res map[string]JSONPather) {
	return Schema(c).JSONChildren()
}

// UnmarshalJSON implements the json.Unmarshaler interface for Contains
func (c *Contains) UnmarshalJSON(data []byte) error {
	var sch Schema
	if err := json.Unmarshal(data, &sch); err != nil {
		return err
	}
	*c = Contains(sch)
	return nil
}

// MaxContains defines the maxContains JSON Schema keyword
type MaxContains int

// NewMaxContains allocates a new MaxContains keyword
func NewMaxContains() Keyword {
	return new(MaxContains)
}

// Register implements the Keyword interface for MaxContains
func (m *MaxContains) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MaxContains
func (m *MaxContains) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MaxContains
func (m MaxContains) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MaxContains] Validating")
	if arr, ok := data.([]interface{}); ok {
		if containsCount, ok := currentState.Misc["containsCount"]; ok {
			if containsCount.(int) > int(m) {
				currentState.AddError(data, fmt.Sprintf("contained items %d exceeds %d max", len(arr), m))
			}
		}
	}
}

// MinContains defines the minContains JSON Schema keyword
type MinContains int

// NewMinContains allocates a new MinContains keyword
func NewMinContains() Keyword {
	return new(MinContains)
}

// Register implements the Keyword interface for MinContains
func (m *MinContains) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MinContains
func (m *MinContains) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MinContains
func (m MinContains) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MinContains] Validating")
	if arr, ok := data.([]interface{}); ok {
		if containsCount, ok := currentState.Misc["containsCount"]; ok {
			if containsCount.(int) < int(m) {
				currentState.AddError(data, fmt.Sprintf("contained items %d bellow %d min", len(arr), m))
			}
		}
	}
}

// AdditionalItems defines the additionalItems JSON Schema keyword
type AdditionalItems Schema

// NewAdditionalItems allocates a new AdditionalItems keyword
func NewAdditionalItems() Keyword {
	return &AdditionalItems{}
}

// Register implements the Keyword interface for AdditionalItems
func (ai *AdditionalItems) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(ai).Register(uri, registry)
}

// Resolve implements the Keyword interface for AdditionalItems
func (ai *AdditionalItems) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(ai).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for AdditionalItems
func (ai *AdditionalItems) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[AdditionalItems] Validating")
	if arr, ok := data.([]interface{}); ok {
		if currentState.LastEvaluatedIndex > -1 && currentState.LastEvaluatedIndex < len(arr) {
			for i := currentState.LastEvaluatedIndex + 1; i < len(arr); i++ {
				if ai.schemaType == schemaTypeFalse {
					currentState.AddError(data, "additional items are not allowed")
					return
				}
				subState := currentState.NewSubState()
				subState.ClearState()
				subState.SetEvaluatedIndex(i)
				subState.DescendBase("additionalItems")
				subState.DescendRelative("additionalItems")
				subState.DescendInstance(strconv.Itoa(i))

				(*Schema)(ai).ValidateKeyword(ctx, subState, arr[i])
				currentState.UpdateEvaluatedPropsAndItems(subState)
			}
		}
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface for AdditionalItems
func (ai *AdditionalItems) UnmarshalJSON(data []byte) error {
	sch := &Schema{}
	if err := json.Unmarshal(data, sch); err != nil {
		return err
	}
	*ai = (AdditionalItems)(*sch)
	return nil
}

// UnevaluatedItems defines the unevaluatedItems JSON Schema keyword
type UnevaluatedItems Schema

// NewUnevaluatedItems allocates a new UnevaluatedItems keyword
func NewUnevaluatedItems() Keyword {
	return &UnevaluatedItems{}
}

// Register implements the Keyword interface for UnevaluatedItems
func (ui *UnevaluatedItems) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(ui).Register(uri, registry)
}

// Resolve implements the Keyword interface for UnevaluatedItems
func (ui *UnevaluatedItems) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(ui).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for UnevaluatedItems
func (ui *UnevaluatedItems) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[UnevaluatedItems] Validating")
	if arr, ok := data.([]interface{}); ok {
		if currentState.LastEvaluatedIndex < len(arr) {
			for i := currentState.LastEvaluatedIndex + 1; i < len(arr); i++ {
				if ui.schemaType == schemaTypeFalse {
					currentState.AddError(data, "unevaluated items are not allowed")
					return
				}
				subState := currentState.NewSubState()
				subState.ClearState()
				subState.DescendBase("unevaluatedItems")
				subState.DescendRelative("unevaluatedItems")
				subState.DescendInstance(strconv.Itoa(i))

				(*Schema)(ui).ValidateKeyword(ctx, subState, arr[i])
			}
		}
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface for UnevaluatedItems
func (ui *UnevaluatedItems) UnmarshalJSON(data []byte) error {
	sch := &Schema{}
	if err := json.Unmarshal(data, sch); err != nil {
		return err
	}
	*ui = (UnevaluatedItems)(*sch)
	return nil
}
