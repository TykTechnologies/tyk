package jsonschema

import (
	jptr "github.com/qri-io/jsonpointer"
)

// ValidationState holds the schema validation state
// The aim is to have one global validation state
// and use local sub states when evaluating parallel branches
// TODO(arqu): make sure this is safe for concurrent use
type ValidationState struct {
	Local                *Schema
	Root                 *Schema
	RecursiveAnchor      *Schema
	BaseURI              string
	InstanceLocation     *jptr.Pointer
	RelativeLocation     *jptr.Pointer
	BaseRelativeLocation *jptr.Pointer

	LocalRegistry *SchemaRegistry

	EvaluatedPropertyNames      *map[string]bool
	LocalEvaluatedPropertyNames *map[string]bool
	LastEvaluatedIndex          int
	LocalLastEvaluatedIndex     int
	Misc                        map[string]interface{}

	Errs *[]KeyError
}

// NewValidationState creates a new ValidationState with the provided location pointers and data instance
func NewValidationState(s *Schema) *ValidationState {
	tmpBRLprt := jptr.NewPointer()
	tmpRLprt := jptr.NewPointer()
	tmpILprt := jptr.NewPointer()
	return &ValidationState{
		Root:                        s,
		BaseRelativeLocation:        &tmpBRLprt,
		RelativeLocation:            &tmpRLprt,
		InstanceLocation:            &tmpILprt,
		LocalRegistry:               &SchemaRegistry{},
		LastEvaluatedIndex:          -1,
		LocalLastEvaluatedIndex:     -1,
		EvaluatedPropertyNames:      &map[string]bool{},
		LocalEvaluatedPropertyNames: &map[string]bool{},
		Misc:                        map[string]interface{}{},
		Errs:                        &[]KeyError{},
	}
}

// NewSubState creates a new ValidationState from an existing ValidationState
func (vs *ValidationState) NewSubState() *ValidationState {
	return &ValidationState{
		Local:                       vs.Local,
		Root:                        vs.Root,
		RecursiveAnchor:             vs.RecursiveAnchor,
		LastEvaluatedIndex:          vs.LastEvaluatedIndex,
		LocalLastEvaluatedIndex:     vs.LocalLastEvaluatedIndex,
		BaseURI:                     vs.BaseURI,
		InstanceLocation:            vs.InstanceLocation,
		RelativeLocation:            vs.RelativeLocation,
		BaseRelativeLocation:        vs.RelativeLocation,
		LocalRegistry:               vs.LocalRegistry,
		EvaluatedPropertyNames:      vs.EvaluatedPropertyNames,
		LocalEvaluatedPropertyNames: vs.LocalEvaluatedPropertyNames,
		Misc:                        map[string]interface{}{},
		Errs:                        vs.Errs,
	}
}

// ClearState resets a schema to it's core elements
func (vs *ValidationState) ClearState() {
	vs.EvaluatedPropertyNames = &map[string]bool{}
	vs.LocalEvaluatedPropertyNames = &map[string]bool{}
	if len(vs.Misc) > 0 {
		vs.Misc = map[string]interface{}{}
	}
}

// SetEvaluatedKey updates the evaluation properties of the current state
func (vs *ValidationState) SetEvaluatedKey(key string) {
	(*vs.EvaluatedPropertyNames)[key] = true
	(*vs.LocalEvaluatedPropertyNames)[key] = true
}

// IsEvaluatedKey checks if the key is evaluated against the state context
func (vs *ValidationState) IsEvaluatedKey(key string) bool {
	_, ok := (*vs.EvaluatedPropertyNames)[key]
	return ok
}

// IsLocallyEvaluatedKey checks if the key is evaluated against the local state context
func (vs *ValidationState) IsLocallyEvaluatedKey(key string) bool {
	_, ok := (*vs.LocalEvaluatedPropertyNames)[key]
	return ok
}

// SetEvaluatedIndex sets the evaluation index for the current state
func (vs *ValidationState) SetEvaluatedIndex(i int) {
	vs.LastEvaluatedIndex = i
	vs.LocalLastEvaluatedIndex = i
}

// UpdateEvaluatedPropsAndItems is a utility function to join evaluated properties and set the
// current evaluation position index
func (vs *ValidationState) UpdateEvaluatedPropsAndItems(subState *ValidationState) {
	joinSets(vs.EvaluatedPropertyNames, *subState.EvaluatedPropertyNames)
	joinSets(vs.LocalEvaluatedPropertyNames, *subState.LocalEvaluatedPropertyNames)
	if subState.LastEvaluatedIndex > vs.LastEvaluatedIndex {
		vs.LastEvaluatedIndex = subState.LastEvaluatedIndex
	}
	if subState.LocalLastEvaluatedIndex > vs.LastEvaluatedIndex {
		vs.LastEvaluatedIndex = subState.LocalLastEvaluatedIndex
	}
}

func copySet(input map[string]bool) map[string]bool {
	copy := make(map[string]bool, len(input))
	for k, v := range input {
		copy[k] = v
	}
	return copy
}

func joinSets(consumer *map[string]bool, supplier map[string]bool) {
	for k, v := range supplier {
		(*consumer)[k] = v
	}
}

// AddError creates and appends a KeyError to errs of the current state
func (vs *ValidationState) AddError(data interface{}, msg string) {
	schemaDebug("[AddError] Error: %s", msg)
	instancePath := vs.InstanceLocation.String()
	if len(instancePath) == 0 {
		instancePath = "/"
	}
	*vs.Errs = append(*vs.Errs, KeyError{
		PropertyPath: instancePath,
		InvalidValue: data,
		Message:      msg,
	})
}

// AddSubErrors appends a list of KeyError to the current state
func (vs *ValidationState) AddSubErrors(errs ...KeyError) {
	for _, err := range errs {
		schemaDebug("[AddSubErrors] Error: %s", err.Message)
	}
	*vs.Errs = append(*vs.Errs, errs...)
}

// IsValid returns if the current state is valid
func (vs *ValidationState) IsValid() bool {
	if vs.Errs == nil {
		return true
	}
	return len(*vs.Errs) == 0
}

// DescendBase descends the base relative pointer relative to itself
func (vs *ValidationState) DescendBase(token ...string) {
	vs.DescendBaseFromState(vs, token...)
}

// DescendBaseFromState descends the base relative pointer relative to the provided state
func (vs *ValidationState) DescendBaseFromState(base *ValidationState, token ...string) {
	if base.BaseRelativeLocation != nil {
		newPtr := base.BaseRelativeLocation.RawDescendant(token...)
		vs.BaseRelativeLocation = &newPtr
	}
}

// DescendRelative descends the relative pointer relative to itself
func (vs *ValidationState) DescendRelative(token ...string) {
	vs.DescendRelativeFromState(vs, token...)
}

// DescendRelativeFromState descends the relative pointer relative to the provided state
func (vs *ValidationState) DescendRelativeFromState(base *ValidationState, token ...string) {
	newPtr := base.InstanceLocation.RawDescendant(token...)
	vs.RelativeLocation = &newPtr
}

// DescendInstance descends the instance pointer relative to itself
func (vs *ValidationState) DescendInstance(token ...string) {
	vs.DescendInstanceFromState(vs, token...)
}

// DescendInstanceFromState descends the instance pointer relative to the provided state
func (vs *ValidationState) DescendInstanceFromState(base *ValidationState, token ...string) {
	newPtr := base.InstanceLocation.RawDescendant(token...)
	vs.InstanceLocation = &newPtr
}
