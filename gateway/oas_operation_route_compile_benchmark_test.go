package gateway

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
)

func BenchmarkGetExtendedPathSpecsOASValidateMockOperations(b *testing.B) {
	for _, operations := range []int{25, 100, 250} {
		b.Run(fmt.Sprintf("operations=%d", operations), func(b *testing.B) {
			versionInfo, spec := benchmarkOASValidateMockOperationSpec(operations)
			conf := &config.Config{}
			loader := APIDefinitionLoader{}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				specs, _ := loader.getExtendedPathSpecs(versionInfo, spec, conf)
				if len(specs) == 0 {
					b.Fatalf("getExtendedPathSpecs(%d operations) returned 0 specs, want validate/mock specs", operations)
				}
			}
		})
	}
}

func benchmarkOASValidateMockOperationSpec(operations int) (apidef.VersionInfo, *APISpec) {
	paths := openapi3.NewPaths()
	tykOperations := make(oas.Operations, operations)

	for i := 0; i < operations; i++ {
		operationID := fmt.Sprintf("getResource%d", i)
		paths.Set(fmt.Sprintf("/resources/%03d/{id}", i), &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: operationID},
		})
		tykOperations[operationID] = &oas.Operation{
			ValidateRequest: &oas.ValidateRequest{Enabled: true},
			MockResponse: &oas.MockResponse{
				Enabled: true,
				Code:    http.StatusOK,
				Body:    `{"ok":true}`,
			},
		}
	}

	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.0",
			Info:    &openapi3.Info{Title: "Benchmark API", Version: "1.0.0"},
			Paths:   paths,
		},
	}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: tykOperations,
		},
	})

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			IsOAS: true,
		},
		OAS: oasAPI,
	}

	return apidef.VersionInfo{UseExtendedPaths: true}, spec
}
