package openapi3

import (
	"context"
	"path/filepath"
	"strings"
)

type RefNameResolver func(string) string

// DefaultRefResolver is a default implementation of refNameResolver for the
// InternalizeRefs function.
//
// If a reference points to an element inside a document, it returns the last
// element in the reference using filepath.Base. Otherwise if the reference points
// to a file, it returns the file name trimmed of all extensions.
func DefaultRefNameResolver(ref string) string {
	if ref == "" {
		return ""
	}
	split := strings.SplitN(ref, "#", 2)
	if len(split) == 2 {
		return filepath.Base(split[1])
	}
	ref = split[0]
	for ext := filepath.Ext(ref); len(ext) > 0; ext = filepath.Ext(ref) {
		ref = strings.TrimSuffix(ref, ext)
	}
	return filepath.Base(ref)
}

func schemaNames(s Schemas) []string {
	out := make([]string, 0, len(s))
	for i := range s {
		out = append(out, i)
	}
	return out
}

func parametersMapNames(s ParametersMap) []string {
	out := make([]string, 0, len(s))
	for i := range s {
		out = append(out, i)
	}
	return out
}

func isExternalRef(ref string) bool {
	return ref != "" && !strings.HasPrefix(ref, "#/components/")
}

func (doc *T) addSchemaToSpec(s *SchemaRef, refNameResolver RefNameResolver) {
	if s == nil || !isExternalRef(s.Ref) {
		return
	}

	name := refNameResolver(s.Ref)
	if _, ok := doc.Components.Schemas[name]; ok {
		s.Ref = "#/components/schemas/" + name
		return
	}

	if doc.Components.Schemas == nil {
		doc.Components.Schemas = make(Schemas)
	}
	doc.Components.Schemas[name] = s.Value.NewRef()
	s.Ref = "#/components/schemas/" + name
}

func (doc *T) addParameterToSpec(p *ParameterRef, refNameResolver RefNameResolver) {
	if p == nil || !isExternalRef(p.Ref) {
		return
	}
	name := refNameResolver(p.Ref)
	if _, ok := doc.Components.Parameters[name]; ok {
		p.Ref = "#/components/parameters/" + name
		return
	}

	if doc.Components.Parameters == nil {
		doc.Components.Parameters = make(ParametersMap)
	}
	doc.Components.Parameters[name] = &ParameterRef{Value: p.Value}
	p.Ref = "#/components/parameters/" + name
}

func (doc *T) addHeaderToSpec(h *HeaderRef, refNameResolver RefNameResolver) {
	if h == nil || !isExternalRef(h.Ref) {
		return
	}
	name := refNameResolver(h.Ref)
	if _, ok := doc.Components.Headers[name]; ok {
		h.Ref = "#/components/headers/" + name
		return
	}
	if doc.Components.Headers == nil {
		doc.Components.Headers = make(Headers)
	}
	doc.Components.Headers[name] = &HeaderRef{Value: h.Value}
	h.Ref = "#/components/headers/" + name
}

func (doc *T) addRequestBodyToSpec(r *RequestBodyRef, refNameResolver RefNameResolver) {
	if r == nil || !isExternalRef(r.Ref) {
		return
	}
	name := refNameResolver(r.Ref)
	if _, ok := doc.Components.RequestBodies[name]; ok {
		r.Ref = "#/components/requestBodies/" + name
		return
	}
	if doc.Components.RequestBodies == nil {
		doc.Components.RequestBodies = make(RequestBodies)
	}
	doc.Components.RequestBodies[name] = &RequestBodyRef{Value: r.Value}
	r.Ref = "#/components/requestBodies/" + name
}

func (doc *T) addResponseToSpec(r *ResponseRef, refNameResolver RefNameResolver) {
	if r == nil || !isExternalRef(r.Ref) {
		return
	}
	name := refNameResolver(r.Ref)
	if _, ok := doc.Components.Responses[name]; ok {
		r.Ref = "#/components/responses/" + name
		return
	}
	if doc.Components.Responses == nil {
		doc.Components.Responses = make(Responses)
	}
	doc.Components.Responses[name] = &ResponseRef{Value: r.Value}
	r.Ref = "#/components/responses/" + name

}

func (doc *T) addSecuritySchemeToSpec(ss *SecuritySchemeRef, refNameResolver RefNameResolver) {
	if ss == nil || !isExternalRef(ss.Ref) {
		return
	}
	name := refNameResolver(ss.Ref)
	if _, ok := doc.Components.SecuritySchemes[name]; ok {
		ss.Ref = "#/components/securitySchemes/" + name
		return
	}
	if doc.Components.SecuritySchemes == nil {
		doc.Components.SecuritySchemes = make(SecuritySchemes)
	}
	doc.Components.SecuritySchemes[name] = &SecuritySchemeRef{Value: ss.Value}
	ss.Ref = "#/components/securitySchemes/" + name

}

func (doc *T) addExampleToSpec(e *ExampleRef, refNameResolver RefNameResolver) {
	if e == nil || !isExternalRef(e.Ref) {
		return
	}
	name := refNameResolver(e.Ref)
	if _, ok := doc.Components.Examples[name]; ok {
		e.Ref = "#/components/examples/" + name
		return
	}
	if doc.Components.Examples == nil {
		doc.Components.Examples = make(Examples)
	}
	doc.Components.Examples[name] = &ExampleRef{Value: e.Value}
	e.Ref = "#/components/examples/" + name

}

func (doc *T) addLinkToSpec(l *LinkRef, refNameResolver RefNameResolver) {
	if l == nil || !isExternalRef(l.Ref) {
		return
	}
	name := refNameResolver(l.Ref)
	if _, ok := doc.Components.Links[name]; ok {
		l.Ref = "#/components/links/" + name
		return
	}
	if doc.Components.Links == nil {
		doc.Components.Links = make(Links)
	}
	doc.Components.Links[name] = &LinkRef{Value: l.Value}
	l.Ref = "#/components/links/" + name

}

func (doc *T) addCallbackToSpec(c *CallbackRef, refNameResolver RefNameResolver) {
	if c == nil || !isExternalRef(c.Ref) {
		return
	}
	name := refNameResolver(c.Ref)
	if _, ok := doc.Components.Callbacks[name]; ok {
		c.Ref = "#/components/callbacks/" + name
	}
	if doc.Components.Callbacks == nil {
		doc.Components.Callbacks = make(Callbacks)
	}
	doc.Components.Callbacks[name] = &CallbackRef{Value: c.Value}
	c.Ref = "#/components/callbacks/" + name
}

func (doc *T) derefSchema(s *Schema, refNameResolver RefNameResolver) {
	if s == nil {
		return
	}

	for _, list := range []SchemaRefs{s.AllOf, s.AnyOf, s.OneOf} {
		for _, s2 := range list {
			doc.addSchemaToSpec(s2, refNameResolver)
			if s2 != nil {
				doc.derefSchema(s2.Value, refNameResolver)
			}
		}
	}
	for _, s2 := range s.Properties {
		doc.addSchemaToSpec(s2, refNameResolver)
		if s2 != nil {
			doc.derefSchema(s2.Value, refNameResolver)
		}
	}
	for _, ref := range []*SchemaRef{s.Not, s.AdditionalProperties, s.Items} {
		doc.addSchemaToSpec(ref, refNameResolver)
		if ref != nil {
			doc.derefSchema(ref.Value, refNameResolver)
		}
	}
}

func (doc *T) derefHeaders(hs Headers, refNameResolver RefNameResolver) {
	for _, h := range hs {
		doc.addHeaderToSpec(h, refNameResolver)
		doc.derefParameter(h.Value.Parameter, refNameResolver)
	}
}

func (doc *T) derefExamples(es Examples, refNameResolver RefNameResolver) {
	for _, e := range es {
		doc.addExampleToSpec(e, refNameResolver)
	}
}

func (doc *T) derefContent(c Content, refNameResolver RefNameResolver) {
	for _, mediatype := range c {
		doc.addSchemaToSpec(mediatype.Schema, refNameResolver)
		if mediatype.Schema != nil {
			doc.derefSchema(mediatype.Schema.Value, refNameResolver)
		}
		doc.derefExamples(mediatype.Examples, refNameResolver)
		for _, e := range mediatype.Encoding {
			doc.derefHeaders(e.Headers, refNameResolver)
		}
	}
}

func (doc *T) derefLinks(ls Links, refNameResolver RefNameResolver) {
	for _, l := range ls {
		doc.addLinkToSpec(l, refNameResolver)
	}
}

func (doc *T) derefResponses(es Responses, refNameResolver RefNameResolver) {
	for _, e := range es {
		doc.addResponseToSpec(e, refNameResolver)
		if e.Value != nil {
			doc.derefHeaders(e.Value.Headers, refNameResolver)
			doc.derefContent(e.Value.Content, refNameResolver)
			doc.derefLinks(e.Value.Links, refNameResolver)
		}
	}
}

func (doc *T) derefParameter(p Parameter, refNameResolver RefNameResolver) {
	doc.addSchemaToSpec(p.Schema, refNameResolver)
	doc.derefContent(p.Content, refNameResolver)
	if p.Schema != nil {
		doc.derefSchema(p.Schema.Value, refNameResolver)
	}
}

func (doc *T) derefRequestBody(r RequestBody, refNameResolver RefNameResolver) {
	doc.derefContent(r.Content, refNameResolver)
}

func (doc *T) derefPaths(paths map[string]*PathItem, refNameResolver RefNameResolver) {
	for _, ops := range paths {
		// inline full operations
		ops.Ref = ""

		for _, op := range ops.Operations() {
			doc.addRequestBodyToSpec(op.RequestBody, refNameResolver)
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				doc.derefRequestBody(*op.RequestBody.Value, refNameResolver)
			}
			for _, cb := range op.Callbacks {
				doc.addCallbackToSpec(cb, refNameResolver)
				if cb.Value != nil {
					doc.derefPaths(*cb.Value, refNameResolver)
				}
			}
			doc.derefResponses(op.Responses, refNameResolver)
			for _, param := range op.Parameters {
				doc.addParameterToSpec(param, refNameResolver)
				if param.Value != nil {
					doc.derefParameter(*param.Value, refNameResolver)
				}
			}
		}
	}
}

// InternalizeRefs removes all references to external files from the spec and moves them
// to the components section.
//
// refNameResolver takes in references to returns a name to store the reference under locally.
// It MUST return a unique name for each reference type.
// A default implementation is provided that will suffice for most use cases. See the function
// documention for more details.
//
// Example:
//
//   doc.InternalizeRefs(context.Background(), nil)
func (doc *T) InternalizeRefs(ctx context.Context, refNameResolver func(ref string) string) {
	if refNameResolver == nil {
		refNameResolver = DefaultRefNameResolver
	}

	// Handle components section
	names := schemaNames(doc.Components.Schemas)
	for _, name := range names {
		schema := doc.Components.Schemas[name]
		doc.addSchemaToSpec(schema, refNameResolver)
		if schema != nil {
			schema.Ref = "" // always dereference the top level
			doc.derefSchema(schema.Value, refNameResolver)
		}
	}
	names = parametersMapNames(doc.Components.Parameters)
	for _, name := range names {
		p := doc.Components.Parameters[name]
		doc.addParameterToSpec(p, refNameResolver)
		if p != nil && p.Value != nil {
			p.Ref = "" // always dereference the top level
			doc.derefParameter(*p.Value, refNameResolver)
		}
	}
	doc.derefHeaders(doc.Components.Headers, refNameResolver)
	for _, req := range doc.Components.RequestBodies {
		doc.addRequestBodyToSpec(req, refNameResolver)
		if req != nil && req.Value != nil {
			req.Ref = "" // always dereference the top level
			doc.derefRequestBody(*req.Value, refNameResolver)
		}
	}
	doc.derefResponses(doc.Components.Responses, refNameResolver)
	for _, ss := range doc.Components.SecuritySchemes {
		doc.addSecuritySchemeToSpec(ss, refNameResolver)
	}
	doc.derefExamples(doc.Components.Examples, refNameResolver)
	doc.derefLinks(doc.Components.Links, refNameResolver)
	for _, cb := range doc.Components.Callbacks {
		doc.addCallbackToSpec(cb, refNameResolver)
		if cb != nil && cb.Value != nil {
			cb.Ref = "" // always dereference the top level
			doc.derefPaths(*cb.Value, refNameResolver)
		}
	}

	doc.derefPaths(doc.Paths, refNameResolver)
}
