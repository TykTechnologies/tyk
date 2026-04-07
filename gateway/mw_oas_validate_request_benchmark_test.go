package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

// BenchmarkSortURLSpecsByPathPriority measures the overhead of sorting URLSpec entries.
func BenchmarkSortURLSpecsByPathPriority(b *testing.B) {
	for _, n := range []int{10, 50, 200} {
		b.Run(fmt.Sprintf("paths=%d", n), func(b *testing.B) {
			// Build a mix of static and parameterised paths
			template := make([]URLSpec, n)
			for i := 0; i < n; i++ {
				if i%3 == 0 {
					template[i] = URLSpec{OASPath: fmt.Sprintf("/api/v1/resource%d/{id}", i)}
				} else {
					template[i] = URLSpec{OASPath: fmt.Sprintf("/api/v1/resource%d/static", i)}
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				specs := make([]URLSpec, n)
				copy(specs, template)
				sortURLSpecsByPathPriority(specs)
			}
		})
	}
}

// BenchmarkOASValidateRequestStaticVsParameterized measures request-time performance
// for static and parameterised paths with the shield mechanism.
func BenchmarkOASValidateRequestStaticVsParameterized(b *testing.B) {
	ts := StartTest(nil)
	defer ts.Close()

	paths := openapi3.NewPaths()

	// Parameterised path with validation
	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUserById",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:     "id",
						In:       "path",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"integer"},
							},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	// Static path without validation
	paths.Set("/users/admin", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getAdminUser",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: stringPtrHelper("Success"),
					},
				}),
			),
		},
	})

	// Add extra static paths to test scaling
	for i := 0; i < 50; i++ {
		opID := fmt.Sprintf("getResource%d", i)
		paths.Set(fmt.Sprintf("/resources/item%d", i), &openapi3.PathItem{
			Get: &openapi3.Operation{
				OperationID: opID,
				Responses: openapi3.NewResponses(
					openapi3.WithStatus(200, &openapi3.ResponseRef{
						Value: &openapi3.Response{
							Description: stringPtrHelper("Success"),
						},
					}),
				),
			},
		})
	}

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info:    &openapi3.Info{Title: "Benchmark API", Version: "1.0.0"},
		Paths:   paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getUserById": {
					ValidateRequest: &oas.ValidateRequest{Enabled: true},
				},
			},
		},
	})

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Benchmark API"
		spec.APIID = "benchmark-api"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})[0]

	require.NotNil(b, api)

	b.Run("StaticPath_ShieldHit", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/api/users/admin", nil)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			ts.TestServerRouter.ServeHTTP(rec, req)
		}
	})

	b.Run("ParameterizedPath_ValidationHit", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/api/users/123", nil)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			ts.TestServerRouter.ServeHTTP(rec, req)
		}
	})
}
