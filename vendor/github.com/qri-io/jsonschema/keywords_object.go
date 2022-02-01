package jsonschema

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	jptr "github.com/qri-io/jsonpointer"
)

// Properties defines the properties JSON Schema keyword
type Properties map[string]*Schema

// NewProperties allocates a new Properties keyword
func NewProperties() Keyword {
	return &Properties{}
}

// Register implements the Keyword interface for Properties
func (p *Properties) Register(uri string, registry *SchemaRegistry) {
	for _, v := range *p {
		v.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for Properties
func (p *Properties) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer == nil {
		return nil
	}
	current := pointer.Head()
	if current == nil {
		return nil
	}

	if schema, ok := (*p)[*current]; ok {
		return schema.Resolve(pointer.Tail(), uri)
	}

	return nil
}

// ValidateKeyword implements the Keyword interface for Properties
func (p Properties) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Properties] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		subState := currentState.NewSubState()
		for key := range p {
			if _, ok := obj[key]; ok {
				currentState.SetEvaluatedKey(key)
				subState.ClearState()
				subState.DescendBaseFromState(currentState, "properties", key)
				subState.DescendRelativeFromState(currentState, "properties", key)
				subState.DescendInstanceFromState(currentState, key)

				subState.Errs = &[]KeyError{}
				p[key].ValidateKeyword(ctx, subState, obj[key])
				currentState.AddSubErrors(*subState.Errs...)
				if subState.IsValid() {
					currentState.UpdateEvaluatedPropsAndItems(subState)
				}
			}
		}
	}
}

// JSONProp implements the JSONPather for Properties
func (p Properties) JSONProp(name string) interface{} {
	return p[name]
}

// JSONChildren implements the JSONContainer interface for Properties
func (p Properties) JSONChildren() (res map[string]JSONPather) {
	res = map[string]JSONPather{}
	for key, sch := range p {
		res[key] = sch
	}
	return
}

// Required defines the required JSON Schema keyword
type Required []string

// NewRequired allocates a new Required keyword
func NewRequired() Keyword {
	return &Required{}
}

// Register implements the Keyword interface for Required
func (r *Required) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Required
func (r *Required) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for Required
func (r Required) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Required] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		for _, key := range r {
			if _, ok := obj[key]; !ok {
				currentState.AddError(data, fmt.Sprintf(`"%s" value is required`, key))
			}
		}
	}
}

// JSONProp implements the JSONPather for Required
func (r Required) JSONProp(name string) interface{} {
	idx, err := strconv.Atoi(name)
	if err != nil {
		return nil
	}
	if idx > len(r) || idx < 0 {
		return nil
	}
	return r[idx]
}

// MaxProperties defines the maxProperties JSON Schema keyword
type MaxProperties int

// NewMaxProperties allocates a new MaxProperties keyword
func NewMaxProperties() Keyword {
	return new(MaxProperties)
}

// Register implements the Keyword interface for MaxProperties
func (m *MaxProperties) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MaxProperties
func (m *MaxProperties) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MaxProperties
func (m MaxProperties) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MaxProperties] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		if len(obj) > int(m) {
			currentState.AddError(data, fmt.Sprintf("%d object Properties exceed %d maximum", len(obj), m))
		}
	}
}

// MinProperties defines the minProperties JSON Schema keyword
type MinProperties int

// NewMinProperties allocates a new MinProperties keyword
func NewMinProperties() Keyword {
	return new(MinProperties)
}

// Register implements the Keyword interface for MinProperties
func (m *MinProperties) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for MinProperties
func (m *MinProperties) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for MinProperties
func (m MinProperties) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[MinProperties] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		if len(obj) < int(m) {
			currentState.AddError(data, fmt.Sprintf("%d object Properties below %d minimum", len(obj), m))
		}
	}
}

// PatternProperties defines the patternProperties JSON Schema keyword
type PatternProperties []patternSchema

// NewPatternProperties allocates a new PatternProperties keyword
func NewPatternProperties() Keyword {
	return &PatternProperties{}
}

type patternSchema struct {
	key    string
	re     *regexp.Regexp
	schema *Schema
}

// Register implements the Keyword interface for PatternProperties
func (p *PatternProperties) Register(uri string, registry *SchemaRegistry) {
	for _, v := range *p {
		v.schema.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for PatternProperties
func (p *PatternProperties) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer == nil {
		return nil
	}
	current := pointer.Head()
	if current == nil {
		return nil
	}

	patProp := &patternSchema{}

	for _, v := range *p {
		if v.key == *current {
			patProp = &v
			break
		}
	}

	return patProp.schema.Resolve(pointer.Tail(), uri)
}

// ValidateKeyword implements the Keyword interface for PatternProperties
func (p PatternProperties) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[PatternProperties] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		for key, val := range obj {
			for _, ptn := range p {
				if ptn.re.Match([]byte(key)) {
					currentState.SetEvaluatedKey(key)
					subState := currentState.NewSubState()
					subState.DescendBase("patternProperties", key)
					subState.DescendRelative("patternProperties", key)
					subState.DescendInstance(key)

					subState.Errs = &[]KeyError{}
					ptn.schema.ValidateKeyword(ctx, subState, val)
					currentState.AddSubErrors(*subState.Errs...)

					if subState.IsValid() {
						currentState.UpdateEvaluatedPropsAndItems(subState)
					}
				}
			}
		}
	}
}

// JSONProp implements the JSONPather for PatternProperties
func (p PatternProperties) JSONProp(name string) interface{} {
	for _, pp := range p {
		if pp.key == name {
			return pp.schema
		}
	}
	return nil
}

// JSONChildren implements the JSONContainer interface for PatternProperties
func (p PatternProperties) JSONChildren() (res map[string]JSONPather) {
	res = map[string]JSONPather{}
	for i, pp := range p {
		res[strconv.Itoa(i)] = pp.schema
	}
	return
}

// UnmarshalJSON implements the json.Unmarshaler interface for PatternProperties
func (p *PatternProperties) UnmarshalJSON(data []byte) error {
	var props map[string]*Schema
	if err := json.Unmarshal(data, &props); err != nil {
		return err
	}

	ptn := make(PatternProperties, len(props))
	i := 0
	for key, sch := range props {
		re, err := regexp.Compile(key)
		if err != nil {
			return fmt.Errorf("invalid pattern: %s: %s", key, err.Error())
		}
		ptn[i] = patternSchema{
			key:    key,
			re:     re,
			schema: sch,
		}
		i++
	}

	*p = ptn
	return nil
}

// MarshalJSON implements the json.Marshaler interface for PatternProperties
func (p PatternProperties) MarshalJSON() ([]byte, error) {
	obj := map[string]interface{}{}
	for _, prop := range p {
		obj[prop.key] = prop.schema
	}
	return json.Marshal(obj)
}

// AdditionalProperties defines the additionalProperties JSON Schema keyword
type AdditionalProperties Schema

// NewAdditionalProperties allocates a new AdditionalProperties keyword
func NewAdditionalProperties() Keyword {
	return &AdditionalProperties{}
}

// Register implements the Keyword interface for AdditionalProperties
func (ap *AdditionalProperties) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(ap).Register(uri, registry)
}

// Resolve implements the Keyword interface for AdditionalProperties
func (ap *AdditionalProperties) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(ap).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for AdditionalProperties
func (ap *AdditionalProperties) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[AdditionalProperties] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		subState := currentState.NewSubState()
		subState.ClearState()
		subState.DescendBase("additionalProperties")
		subState.DescendRelative("additionalProperties")
		for key := range obj {
			if currentState.IsLocallyEvaluatedKey(key) {
				continue
			}
			if ap.schemaType == schemaTypeFalse {
				currentState.AddError(data, "additional properties are not allowed")
				return
			}
			currentState.SetEvaluatedKey(key)
			subState.ClearState()
			subState.DescendInstanceFromState(currentState, key)

			(*Schema)(ap).ValidateKeyword(ctx, subState, obj[key])
			currentState.UpdateEvaluatedPropsAndItems(subState)
		}
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface for AdditionalProperties
func (ap *AdditionalProperties) UnmarshalJSON(data []byte) error {
	sch := &Schema{}
	if err := json.Unmarshal(data, sch); err != nil {
		return err
	}
	*ap = (AdditionalProperties)(*sch)
	return nil
}

// PropertyNames defines the propertyNames JSON Schema keyword
type PropertyNames Schema

// NewPropertyNames allocates a new PropertyNames keyword
func NewPropertyNames() Keyword {
	return &PropertyNames{}
}

// Register implements the Keyword interface for PropertyNames
func (p *PropertyNames) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(p).Register(uri, registry)
}

// Resolve implements the Keyword interface for PropertyNames
func (p *PropertyNames) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(p).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for PropertyNames
func (p *PropertyNames) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[PropertyNames] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		for key := range obj {
			subState := currentState.NewSubState()
			subState.DescendBase("propertyNames")
			subState.DescendRelative("propertyNames")
			subState.DescendInstance(key)
			(*Schema)(p).ValidateKeyword(ctx, subState, key)
		}
	}
}

// JSONProp implements the JSONPather for PropertyNames
func (p PropertyNames) JSONProp(name string) interface{} {
	return Schema(p).JSONProp(name)
}

// JSONChildren implements the JSONContainer interface for PropertyNames
func (p PropertyNames) JSONChildren() (res map[string]JSONPather) {
	return Schema(p).JSONChildren()
}

// UnmarshalJSON implements the json.Unmarshaler interface for PropertyNames
func (p *PropertyNames) UnmarshalJSON(data []byte) error {
	var sch Schema
	if err := json.Unmarshal(data, &sch); err != nil {
		return err
	}
	*p = PropertyNames(sch)
	return nil
}

// MarshalJSON implements the json.Marshaler interface for PropertyNames
func (p PropertyNames) MarshalJSON() ([]byte, error) {
	return json.Marshal(Schema(p))
}

// DependentSchemas defines the dependentSchemas JSON Schema keyword
type DependentSchemas map[string]SchemaDependency

// NewDependentSchemas allocates a new DependentSchemas keyword
func NewDependentSchemas() Keyword {
	return &DependentSchemas{}
}

// Register implements the Keyword interface for DependentSchemas
func (d *DependentSchemas) Register(uri string, registry *SchemaRegistry) {
	for _, v := range *d {
		v.schema.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for DependentSchemas
func (d *DependentSchemas) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer == nil {
		return nil
	}
	current := pointer.Head()
	if current == nil {
		return nil
	}

	if schema, ok := (*d)[*current]; ok {
		return schema.Resolve(pointer.Tail(), uri)
	}

	return nil
}

// ValidateKeyword implements the Keyword interface for DependentSchemas
func (d *DependentSchemas) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[DependentSchemas] Validating")
	for _, v := range *d {
		subState := currentState.NewSubState()
		subState.DescendBase("dependentSchemas")
		subState.DescendRelative("dependentSchemas")
		subState.Misc["dependencyParent"] = "dependentSchemas"
		v.ValidateKeyword(ctx, subState, data)
	}
}

type _dependentSchemas map[string]Schema

// UnmarshalJSON implements the json.Unmarshaler interface for DependentSchemas
func (d *DependentSchemas) UnmarshalJSON(data []byte) error {
	_d := _dependentSchemas{}
	if err := json.Unmarshal(data, &_d); err != nil {
		return err
	}
	ds := DependentSchemas{}
	for k, v := range _d {
		sch := Schema(v)
		ds[k] = SchemaDependency{
			schema: &sch,
			prop:   k,
		}
	}
	*d = ds
	return nil
}

// JSONProp implements the JSONPather for DependentSchemas
func (d DependentSchemas) JSONProp(name string) interface{} {
	return d[name]
}

// JSONChildren implements the JSONContainer interface for DependentSchemas
func (d DependentSchemas) JSONChildren() (r map[string]JSONPather) {
	r = map[string]JSONPather{}
	for key, val := range d {
		r[key] = val
	}
	return
}

// SchemaDependency is the internal representation of a dependent schema
type SchemaDependency struct {
	schema *Schema
	prop   string
}

// Register implements the Keyword interface for SchemaDependency
func (d *SchemaDependency) Register(uri string, registry *SchemaRegistry) {
	d.schema.Register(uri, registry)
}

// Resolve implements the Keyword interface for SchemaDependency
func (d *SchemaDependency) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return d.schema.Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for SchemaDependency
func (d *SchemaDependency) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[SchemaDependency] Validating")
	depsData := map[string]interface{}{}
	ok := false
	if depsData, ok = data.(map[string]interface{}); !ok {
		return
	}
	if _, okProp := depsData[d.prop]; !okProp {
		return
	}
	subState := currentState.NewSubState()
	subState.DescendBase(d.prop)
	subState.DescendRelative(d.prop)
	d.schema.ValidateKeyword(ctx, subState, data)
}

// MarshalJSON implements the json.Marshaler interface for SchemaDependency
func (d SchemaDependency) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.schema)
}

// JSONProp implements the JSONPather for SchemaDependency
func (d SchemaDependency) JSONProp(name string) interface{} {
	return d.schema.JSONProp(name)
}

// DependentRequired defines the dependentRequired JSON Schema keyword
type DependentRequired map[string]PropertyDependency

// NewDependentRequired allocates a new DependentRequired keyword
func NewDependentRequired() Keyword {
	return &DependentRequired{}
}

// Register implements the Keyword interface for DependentRequired
func (d *DependentRequired) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for DependentRequired
func (d *DependentRequired) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for DependentRequired
func (d *DependentRequired) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[DependentRequired] Validating")
	for _, prop := range *d {
		subState := currentState.NewSubState()
		subState.DescendBase("dependentRequired")
		subState.DescendRelative("dependentRequired")
		subState.Misc["dependencyParent"] = "dependentRequired"
		prop.ValidateKeyword(ctx, subState, data)
	}
}

type _dependentRequired map[string][]string

// UnmarshalJSON implements the json.Unmarshaler interface for DependentRequired
func (d *DependentRequired) UnmarshalJSON(data []byte) error {
	_d := _dependentRequired{}
	if err := json.Unmarshal(data, &_d); err != nil {
		return err
	}
	dr := DependentRequired{}
	for k, v := range _d {
		dr[k] = PropertyDependency{
			dependencies: v,
			prop:         k,
		}
	}
	*d = dr
	return nil
}

// MarshalJSON implements the json.Marshaler interface for DependentRequired
func (d DependentRequired) MarshalJSON() ([]byte, error) {
	obj := map[string]interface{}{}
	for key, prop := range d {
		obj[key] = prop.dependencies
	}
	return json.Marshal(obj)
}

// JSONProp implements the JSONPather for DependentRequired
func (d DependentRequired) JSONProp(name string) interface{} {
	return d[name]
}

// JSONChildren implements the JSONContainer interface for DependentRequired
func (d DependentRequired) JSONChildren() (r map[string]JSONPather) {
	r = map[string]JSONPather{}
	for key, val := range d {
		r[key] = val
	}
	return
}

// PropertyDependency is the internal representation of a dependent property
type PropertyDependency struct {
	dependencies []string
	prop         string
}

// Register implements the Keyword interface for PropertyDependency
func (p *PropertyDependency) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for PropertyDependency
func (p *PropertyDependency) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for PropertyDependency
func (p *PropertyDependency) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[PropertyDependency] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		if obj[p.prop] == nil {
			return
		}
		for _, dep := range p.dependencies {
			if obj[dep] == nil {
				currentState.AddError(data, fmt.Sprintf(`"%s" property is required`, dep))
			}
		}
	}
}

// JSONProp implements the JSONPather for PropertyDependency
func (p PropertyDependency) JSONProp(name string) interface{} {
	idx, err := strconv.Atoi(name)
	if err != nil {
		return nil
	}
	if idx > len(p.dependencies) || idx < 0 {
		return nil
	}
	return p.dependencies[idx]
}

// UnevaluatedProperties defines the unevaluatedProperties JSON Schema keyword
type UnevaluatedProperties Schema

// NewUnevaluatedProperties allocates a new UnevaluatedProperties keyword
func NewUnevaluatedProperties() Keyword {
	return &UnevaluatedProperties{}
}

// Register implements the Keyword interface for UnevaluatedProperties
func (up *UnevaluatedProperties) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(up).Register(uri, registry)
}

// Resolve implements the Keyword interface for UnevaluatedProperties
func (up *UnevaluatedProperties) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(up).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for UnevaluatedProperties
func (up *UnevaluatedProperties) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[UnevaluatedProperties] Validating")
	if obj, ok := data.(map[string]interface{}); ok {
		subState := currentState.NewSubState()
		subState.ClearState()
		subState.DescendBase("unevaluatedProperties")
		subState.DescendRelative("unevaluatedProperties")
		for key := range obj {
			if currentState.IsEvaluatedKey(key) {
				continue
			}
			if up.schemaType == schemaTypeFalse {
				currentState.AddError(data, "unevaluated properties are not allowed")
				return
			}
			subState.DescendInstanceFromState(currentState, key)

			(*Schema)(up).ValidateKeyword(ctx, subState, obj[key])
		}
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface for UnevaluatedProperties
func (up *UnevaluatedProperties) UnmarshalJSON(data []byte) error {
	sch := &Schema{}
	if err := json.Unmarshal(data, sch); err != nil {
		return err
	}
	*up = (UnevaluatedProperties)(*sch)
	return nil
}
