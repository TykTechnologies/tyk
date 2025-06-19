package pathnormalizer

import (
	"github.com/getkin/kin-openapi/openapi3"
	"strings"
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
		normalized, err := parser.Parse(userPath)

		if err != nil {
			return nil, err
		}

		// process custom params from command line
		for _, parameterRef := range normalized.ParameterRefs() {
			pathItem.Parameters = append(pathItem.Parameters, parameterRef)
		}

		// todo: set identifier to an action????
		//
		newPaths.Set(normalized.path, pathItem)
	}

	return newPaths, nil
}
