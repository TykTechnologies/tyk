package pathnormalizer

import (
	"github.com/getkin/kin-openapi/openapi3"
	"strings"
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
