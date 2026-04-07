package gateway

import (
	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/regexp"
)

// extractOASPathParamSchemas collects path parameter schemas from both path-item
// level and operation level parameters. Operation-level parameters override
// path-item level parameters with the same name.
func extractOASPathParamSchemas(pathItem *openapi3.PathItem, operation *openapi3.Operation) map[string]httputil.ParamSchema {
	schemas := make(map[string]httputil.ParamSchema)

	// Path-item level parameters (shared across methods).
	collectPathParams(pathItem.Parameters, schemas)

	// Operation-level parameters override path-item level.
	if operation != nil {
		collectPathParams(operation.Parameters, schemas)
	}

	if len(schemas) == 0 {
		return nil
	}
	return schemas
}

// collectPathParams adds "path" parameters from params into dst.
func collectPathParams(params openapi3.Parameters, dst map[string]httputil.ParamSchema) {
	for _, ref := range params {
		if ref == nil || ref.Value == nil {
			continue
		}
		p := ref.Value
		if p.In != "path" {
			continue
		}

		ps := httputil.ParamSchema{}
		if p.Schema != nil && p.Schema.Value != nil {
			ps.Pattern = p.Schema.Value.Pattern
			if p.Schema.Value.Type != nil && len(*p.Schema.Value.Type) > 0 {
				ps.Type = (*p.Schema.Value.Type)[0]
			}
		}
		dst[p.Name] = ps
	}
}

// compileSubSpec builds a sub-spec regex for a parameterised path using the
// provided parameter schemas and gateway configuration flags.
// Returns nil if the path is static or has no parameter schemas.
func compileSubSpec(path string, paramSchemas map[string]httputil.ParamSchema, conf config.Config) *regexp.Regexp {
	return httputil.CompileSubSpec(
		path,
		paramSchemas,
		conf.HttpServerOptions.EnablePathPrefixMatching,
		conf.HttpServerOptions.EnablePathSuffixMatching,
	)
}

// findOASOperation returns the pathItem and operation for the given path and method.
// It uses exact map lookup (not paths.Find) to avoid template normalization
// which would conflate paths like /employees/{prct} and /employees/{zd}.
func findOASOperation(paths *openapi3.Paths, path, method string) (*openapi3.PathItem, *openapi3.Operation) {
	if paths == nil {
		return nil, nil
	}
	pathItem := paths.Map()[path]
	if pathItem == nil {
		return nil, nil
	}
	ops := pathItem.Operations()
	if ops == nil {
		return pathItem, nil
	}
	return pathItem, ops[method]
}
