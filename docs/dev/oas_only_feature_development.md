# OAS-Only Feature Development Guide

## Overview

This guide outlines the standard approach for developing new features that exclusively use OpenAPI Specification (OAS) in Tyk. This approach helps reduce technical debt by moving away from dual configurations (classic API definition and OAS) to a single source of truth using OAS.

## Architecture

### Core Components

1. **APISpec Structure**
```
type APISpec struct {
    *apidef.APIDefinition
    OAS oas.OAS
    
    // Helper method for retrieving OAS features
    func (s *APISpec) GetTykExtension() *XTykAPIGateway {
      ...
    }
}
```

2. **Tyk Extension in OAS**
```
type XTykAPIGateway struct {
    Info       Info       `json:"info"`
    Upstream   Upstream   `json:"upstream"`
    Server     Server     `json:"server"`
    Middleware *Middleware `json:"middleware,omitempty"`
}
```

## Development Guidelines

### 1. Feature Configuration

1. Add your feature configuration to the `XTykAPIGateway` structure:

```
type XTykAPIGateway struct {
    // Existing fields...
    Middleware *Middleware `json:"middleware,omitempty"`
    
    // New feature configuration
    MyNewFeature *MyNewFeatureConfig `json:"myNewFeature,omitempty"`
}

type MyNewFeatureConfig struct {
    Enabled bool `json:"enabled"`
    // Feature-specific configuration
}
```

### 2. Middleware Implementation

1. Create a new middleware structure:

```
type MyFeatureMiddleware struct {
    BaseMiddleware
}

func NewMyFeatureMiddleware() *MyFeatureMiddleware {
    return &MyFeatureMiddleware{}
}
```

2. Implement the ProcessRequest method:

```
func (m *MyFeatureMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
    if !m.Spec.APIDefinition.IsOAS {
        // Feature only available for OAS APIs
        return nil, http.StatusOK
    }

    tykExt := m.Spec.GetTykExtension()
    if tykExt.MyNewFeature == nil || !tykExt.MyNewFeature.Enabled {
        return nil, http.StatusOK
    }

    // Implement feature logic here
    return m.handleFeature(w, r, tykExt.MyNewFeature)
}
```

### 3. Testing Strategy

Testing OAS-only features requires special attention to how the feature behaves with different API definition types. Focus on these key scenarios:

```
func TestMyFeatureMiddleware(t *testing.T) {
    tests := []struct {
        name           string
        setupAPI       func() *APISpec
        expectedCode   int
        expectedError  error
        description    string
    }{
        {
            name: "classic_api_definition",
            setupAPI: func() *APISpec {
                return &APISpec{
                    APIDefinition: &apidef.APIDefinition{
                        IsOAS: false,
                    },
                }
            },
            expectedCode: http.StatusOK,
            expectedError: nil,
            description: "Should pass through silently for classic APIs",
        },
        {
            name: "nil_oas_definition",
            setupAPI: func() *APISpec {
                return &APISpec{
                    APIDefinition: &apidef.APIDefinition{
                        IsOAS: true,
                    },
                    OAS: oas.OAS{}, // Empty OAS
                }
            },
            expectedCode: http.StatusOK,
            expectedError: nil,
            description: "Should handle nil OAS gracefully",
        },
        {
            name: "valid_oas_definition",
            setupAPI: func() *APISpec {
                return &APISpec{
                    APIDefinition: &apidef.APIDefinition{
                        IsOAS: true,
                    },
                    OAS: createValidOAS(), // Helper to create OAS with your feature enabled
                }
            },
            expectedCode: http.StatusOK,
            expectedError: nil,
            description: "Should process feature when properly configured",
        },
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            mw := NewMyFeatureMiddleware()
            mw.Spec = tc.setupAPI()
            
            err, code := mw.ProcessRequest(nil, &http.Request{}, nil)
            
            assert.Equal(t, tc.expectedError, err)
            assert.Equal(t, tc.expectedCode, code)
        })
    }
}
```

The test cases above cover:
1. Classic API definitions (should pass through)
2. OAS APIs with nil or empty feature configuration
3. OAS APIs with valid feature configuration

Each test verifies that the middleware:
- Handles invalid states gracefully
- Returns appropriate status codes
- Doesn't panic on nil values
- Processes valid configurations correctly

### 4. Documentation Requirements

1. **API Documentation**
   - Document your feature in the Tyk API documentation
   - Include OpenAPI extension examples
   - Provide clear configuration options

2. **Code Documentation**
   - Add godoc comments to all exported types and functions
   - Include examples in code documentation
   - Document any non-obvious behaviors or edge cases

## Best Practices

1. **Configuration**
   - Implement sensible defaults
   - Validate configurations early

2**Testing**
   - Achieve >80% code coverage
   - Test edge cases and error conditions
   - Include performance benchmarks for critical paths

## Backward Compatibility

While OAS-only features don't need classic API definition support, ensure:

1. Feature gracefully handles classic API definitions
2. Clear documentation about OAS-only support
3. Appropriate error messages for unsupported configurations

## Release Considerations

1**Migration**
   - Provide migration guides if replacing existing functionality
   - Include validation tools for configuration
   - Document