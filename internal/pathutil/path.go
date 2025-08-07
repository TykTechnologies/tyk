package pathutil

import (
	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/samber/lo"
	"strings"
)

const (
	notFound = -1
)

type Path struct {
	path       string
	parameters []*openapi3.Parameter
	parts      []pathPart
}

// parsePath responsible for parsing single path
func parsePath(in string) (*Path, error) {
	return NewParser().Parse(in)
}

func newNormalizedPath(parts []pathPart) *Path {
	var sb strings.Builder
	var np Path

	for _, part := range parts {
		sb.WriteString(part.normalize())

		if part.parameter != nil {
			np.parameters = append(np.parameters, part.parameter)
		}
	}

	np.path = sb.String()
	np.parts = parts

	return &np
}

// HasParams returns true if path has path-based parameters.
func (o Path) HasParams() bool {
	return len(o.parameters) != 0
}

// HasReParams returns true if it has classic based regex parameters defined in path
func (o Path) HasReParams() bool {
	return lo.SomeBy(o.parts, func(p pathPart) bool {
		return p.typ == pathPartRe
	})
}

// Parameters slices of path-based params.
func (o Path) Parameters() []*openapi3.Parameter {
	return reflect.Clone(o.parameters)
}

// OperationId create operation id by method name.
func (o Path) OperationId(method string) string {
	return o.RawOpIdPrefix() + strings.ToUpper(method)
}

// RawOpIdPrefix returns prefix.
func (o Path) RawOpIdPrefix() string {
	return strings.TrimPrefix(o.path, string(slash))
}

// PropagateTo takes existent parameters and propagates them to destination if those do not exist.
func (o Path) PropagateTo(dest openapi3.Parameters) {
	if !o.HasParams() {
		return
	}

	if dest == nil {
		dest = openapi3.Parameters{}
	}

	wrapParameters(&dest).extendBy(o.parameterRefs())
}

// parameterRefs slices of path-based params.
func (o Path) parameterRefs() []*openapi3.ParameterRef {
	return lo.Map(o.parameters, func(parameter *openapi3.Parameter, _ int) *openapi3.ParameterRef {
		return &openapi3.ParameterRef{
			Value: reflect.Clone(parameter),
		}
	})
}
