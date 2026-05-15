package graphql_federation

import (
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/v2/pkg/federation"

	"github.com/TykTechnologies/tyk/apidef"
)

// augmentFederationSchema injects the Apollo Federation v2 extensions
// (`_Entity` union, `_entities`, `_service`) into the customer's SDL when the
// API is configured for federation.
//
// UDG (`ExecutionEngine`) composes upstreams locally and always augments.
// Proxy-only (`ProxyOnly`) forwards `_entities` queries to an upstream
// subgraph or router, but Tyk still validates the operation against its
// known schema first; in that case we auto-detect federation by scanning for
// `@key` directives — no config flag.
func augmentFederationSchema(schemaStr string, executionMode apidef.GraphQLExecutionMode) (string, error) {
	switch executionMode {
	case apidef.GraphQLExecutionModeExecutionEngine:
		augmented, err := federation.BuildFederationSchema(schemaStr, schemaStr)
		if err != nil {
			return schemaStr, err
		}
		return augmented, nil
	case apidef.GraphQLExecutionModeProxyOnly:
		// Apollo Federation v2 proxy-mode passthrough: when the customer's
		// SDL declares `@key` types, Tyk forwards `_entities` queries to the
		// upstream subgraph or router. Tyk still validates the operation
		// against its known schema first, so we must inject the federation
		// extensions (`_Entity` union, `_entities`, `_service`) here.
		// Auto-detect from `@key` — no config flag.
		if !schemaHasKeyDirective(schemaStr) {
			return schemaStr, nil
		}
		augmented, err := federation.BuildFederationSchema(schemaStr, schemaStr)
		if err != nil {
			return schemaStr, err
		}
		return augmented, nil
	}
	return schemaStr, nil
}

// schemaHasKeyDirective parses the given SDL and reports whether any object
// type definition or extension carries the `@key` directive. This is the
// auto-detection signal for Apollo Federation v2 in proxy mode — no config
// flag is required.
func schemaHasKeyDirective(sdl string) bool {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return false
	}
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		if !def.HasDirectives {
			continue
		}
		for _, dRef := range def.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				return true
			}
		}
	}
	for i := range doc.ObjectTypeExtensions {
		ext := doc.ObjectTypeExtensions[i]
		if !ext.HasDirectives {
			continue
		}
		for _, dRef := range ext.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				return true
			}
		}
	}
	return false
}

// keyedEntityTypes returns the set of object type names carrying a `@key`
// directive. Mirrors `schemaHasKeyDirective` but yields the names — used by
// the entity-resolver build path and proxy-mode federation detection.
func keyedEntityTypes(sdl string) (map[string]bool, error) {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return nil, report
	}
	out := map[string]bool{}
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		if !def.HasDirectives {
			continue
		}
		for _, dRef := range def.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				out[doc.ObjectTypeDefinitionNameString(i)] = true
				break
			}
		}
	}
	for i := range doc.ObjectTypeExtensions {
		ext := doc.ObjectTypeExtensions[i]
		if !ext.HasDirectives {
			continue
		}
		for _, dRef := range ext.Directives.Refs {
			if doc.DirectiveNameString(dRef) == "key" {
				out[doc.ObjectTypeExtensionNameString(i)] = true
				break
			}
		}
	}
	return out, nil
}

// countKeyDirectives walks the SDL and returns the per-type count of `@key`
// directives. Used to reject the multi-@key case at API load time — the UDG
// entity resolver only supports one key per type, and silently picking one
// (which is what `entitySelectionInfo` used to do) hides config errors.
func countKeyDirectives(sdl string) (map[string]int, error) {
	doc, report := astparser.ParseGraphqlDocumentString(sdl)
	if report.HasErrors() {
		return nil, report
	}
	out := map[string]int{}
	count := func(name string, hasDirectives bool, dirRefs []int) {
		if !hasDirectives {
			return
		}
		for _, dRef := range dirRefs {
			if doc.DirectiveNameString(dRef) == "key" {
				out[name]++
			}
		}
	}
	for i := range doc.ObjectTypeDefinitions {
		def := doc.ObjectTypeDefinitions[i]
		dirRefs := []int{}
		if def.HasDirectives {
			dirRefs = def.Directives.Refs
		}
		count(doc.ObjectTypeDefinitionNameString(i), def.HasDirectives, dirRefs)
	}
	for i := range doc.ObjectTypeExtensions {
		ext := doc.ObjectTypeExtensions[i]
		dirRefs := []int{}
		if ext.HasDirectives {
			dirRefs = ext.Directives.Refs
		}
		// Aggregate across base type and extensions: an extension's keys count
		// alongside the base type's.
		count(doc.ObjectTypeExtensionNameString(i), ext.HasDirectives, dirRefs)
	}
	return out, nil
}
