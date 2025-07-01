package pathnormalizer

import (
	"errors"
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/getkin/kin-openapi/openapi3"
	"strings"
)

var (
	ErrParameterCollision = errors.New("parameter collision")
)

const (
	notFound = -1
)

type NormalizedPath struct {
	path       string
	parameters []*openapi3.Parameter
}

func newNormalizedPath(parts []pathPart) *NormalizedPath {
	var sb strings.Builder
	var np NormalizedPath

	for _, part := range parts {
		sb.WriteString(part.normalize())

		if part.parameter != nil {
			np.parameters = append(np.parameters, part.parameter)
		}
	}

	np.path = sb.String()

	return &np
}

// HasParams returns true if path has path-based parameters.
func (o NormalizedPath) HasParams() bool {
	return len(o.parameters) != 0
}

// Parameters slices of path-based params.
func (o NormalizedPath) Parameters() []*openapi3.Parameter {
	return o.parameters
}

// ParameterRefs slices of path-based params.
func (o NormalizedPath) ParameterRefs() []*openapi3.ParameterRef {
	if len(o.parameters) == 0 {
		return nil
	}

	res := make([]*openapi3.ParameterRef, 0, len(o.parameters))

	for _, p := range o.parameters {
		res = append(res, &openapi3.ParameterRef{Value: p})
	}

	return res
}

// OperationId create operation id by method name.
func (o NormalizedPath) OperationId(method string) string {
	return o.RawOpIdPrefix() + strings.ToUpper(method)
}

// RawOpIdPrefix returns prefix.
func (o NormalizedPath) RawOpIdPrefix() string {
	return strings.TrimPrefix(o.path, string(slash))
}

// Validate validates paths keys can be normalized from user-defined keys to proper ones.
func Validate(paths *openapi3.Paths) error {
	_, err := Normalize(paths)
	return err
}

func Normalize(paths *openapi3.Paths) (*openapi3.Paths, error) {
	newPaths := openapi3.NewPaths()
	parser := NewParser()

	for userPath, pathItem := range paths.Map() {
		userPathClone := reflect.Clone(userPath)
		normalized, err := parser.Parse(userPathClone)

		if err != nil {
			return nil, err
		}

		// process custom params from command line
		pathItemClone := reflect.Clone(pathItem)
		params := parameters{&pathItemClone.Parameters}

		for _, parameterRef := range normalized.ParameterRefs() {
			params.replaceOrAppend(parameterRef)
		}

		newPaths.Set(normalized.path, pathItemClone)
	}

	return newPaths, nil
}

type parameters struct {
	*openapi3.Parameters
}

func (p *parameters) replaceOrAppend(pRef *openapi3.ParameterRef) {
	if pRef.Value == nil {
		*p.Parameters = append(*p.Parameters, pRef)
		return
	}

	if _, idx := p.find(pRef.Value.Name); idx == notFound {
		*p.Parameters = append(*p.Parameters, pRef)
	} else {
		// It seems that more sophisticated logic can be placed here.
		// e.g. prioritize some fields from existing or new entry.
		p.extendExistent(pRef, idx)
	}
}

func (p *parameters) find(name string) (*openapi3.ParameterRef, int) {
	for idx, param := range *p.Parameters {
		if param.Value == nil {
			continue
		}

		if param.Value.Name == name {
			return param, idx
		}
	}

	return nil, notFound
}

func (p *parameters) extendExistent(newRef *openapi3.ParameterRef, idx int) {
	existent := (*p.Parameters)[idx]

	switch {
	case existent.Value == nil:
		(*p.Parameters)[idx] = newRef

	case isTypeOf(existent, openapi3.TypeString) &&
		isTypeOf(newRef, openapi3.TypeString) &&
		isPatternDefined(existent):

	case !isTypeOf(existent, openapi3.TypeString):
		// prefer type from input
		return

	case isDefinedSchemaValue(existent) &&
		isDefinedSchemaValue(newRef) &&
		isTypeOf(existent, openapi3.TypeString) &&
		isTypeOf(newRef, openapi3.TypeString) &&
		!isPatternDefined(existent) &&
		isPatternDefined(newRef):
		existent.Value.Schema.Value.Pattern = newRef.Value.Schema.Value.Pattern

	default:
		(*p.Parameters)[idx] = newRef
	}
}

func isDefinedSchemaValue(ref *openapi3.ParameterRef) bool {
	return ref != nil && ref.Value != nil && ref.Value.Schema != nil && ref.Value.Schema.Value != nil
}

func isTypeOf(ref *openapi3.ParameterRef, expectedType string) bool {
	if !isDefinedSchemaValue(ref) {
		return false
	}

	for _, typ := range *(ref.Value.Schema.Value.Type) {
		if typ == expectedType {
			return true
		}
	}

	return false
}

func isPatternDefined(ref *openapi3.ParameterRef) bool {
	if !isDefinedSchemaValue(ref) {
		return false
	}

	return len(ref.Value.Schema.Value.Pattern) > 0
}
