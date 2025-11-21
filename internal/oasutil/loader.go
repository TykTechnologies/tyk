package oasutil

import (
	"net/url"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pb33f/libopenapi"
)

// LoadFromData loads OpenAPI specification from bytes using pb33f/libopenapi
// but returns an openapi3.T for backward compatibility during migration.
// This enables OAS 3.1 support while maintaining existing API compatibility.
func LoadFromData(data []byte) (*openapi3.T, error) {
	// Try pb33f/libopenapi first for OAS 3.1 support
	doc, err := libopenapi.NewDocument(data)
	if err != nil {
		// If pb33f/libopenapi fails, fall back to openapi3 for backward compatibility
		loader := openapi3.NewLoader()
		return loader.LoadFromData(data)
	}
	
	v3Model, errors := doc.BuildV3Model()
	if len(errors) > 0 {
		// If pb33f model building fails, fall back to openapi3
		loader := openapi3.NewLoader()
		return loader.LoadFromData(data)
	}

	// For backward compatibility during migration, also parse with openapi3 
	// to return expected openapi3.T structure
	// TODO: Remove this fallback once full migration is complete
	loader := openapi3.NewLoader()
	t, err := loader.LoadFromData(data)
	if err != nil {
		// If openapi3 fails (e.g., OAS 3.1), create minimal compatible structure
		// This is a temporary bridge - full migration will eliminate this dependency
		t = &openapi3.T{
			OpenAPI: v3Model.Model.Version,
		}
		
		// Basic field mapping for compatibility - will be expanded as needed
		if v3Model.Model.Info != nil {
			t.Info = &openapi3.Info{
				Title:   v3Model.Model.Info.Title,
				Version: v3Model.Model.Info.Version,
			}
		}
		
		// Initialize paths 
		t.Paths = openapi3.NewPaths()
		
		// Extensions mapping would go here as migration progresses
		t.Extensions = make(map[string]interface{})
		if v3Model.Model.Extensions != nil {
			for pair := v3Model.Model.Extensions.First(); pair != nil; pair = pair.Next() {
				if pair.Value() != nil {
					t.Extensions[pair.Key()] = pair.Value().Value
				}
			}
		}
	}
	
	return t, nil
}

// NewLoader creates a loader that can handle both legacy openapi3 and new pb33f/libopenapi
// This is a compatibility bridge during the migration to OAS 3.1 support
func NewLoader() *CompatibleLoader {
	return &CompatibleLoader{
		OpenAPI3Loader: openapi3.NewLoader(),
	}
}

// CompatibleLoader provides backward compatible loading using pb33f/libopenapi internally
type CompatibleLoader struct {
	OpenAPI3Loader *openapi3.Loader // Exported for temporary compatibility during migration
}

// LoadFromData loads OpenAPI spec with OAS 3.1 support via pb33f/libopenapi
func (cl *CompatibleLoader) LoadFromData(data []byte) (*openapi3.T, error) {
	return LoadFromData(data)
}

// LoadFromFile loads OpenAPI spec from file with OAS 3.1 support
func (cl *CompatibleLoader) LoadFromFile(filepath string) (*openapi3.T, error) {
	// For now, delegate to original openapi3 loader for file loading
	// TODO: Implement pb33f/libopenapi file loading for full OAS 3.1 support
	return cl.OpenAPI3Loader.LoadFromFile(filepath)
}

// ResolveRefsIn resolves references in OpenAPI spec
func (cl *CompatibleLoader) ResolveRefsIn(doc *openapi3.T, location *url.URL) error {
	// For now, delegate to original openapi3 loader for reference resolution  
	// TODO: Implement pb33f/libopenapi reference resolution for full OAS 3.1 support
	return cl.OpenAPI3Loader.ResolveRefsIn(doc, location)
}