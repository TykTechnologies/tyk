package pathnormalizer

import "github.com/getkin/kin-openapi/openapi3"

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
