package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef/oas"
)

func BenchmarkOASValidateRequest_StaticVsParameterizedPath(b *testing.B) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create OAS with two paths:
	// 1. /users/{id} - parameterized, with ValidateRequest enabled
	// 2. /users/admin - static, without ValidateRequest
	paths := openapi3.NewPaths()
	
	// Parameterized path
	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUserById",
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name: "id",
						In:   "path",
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
						Description: ptrStr("Success"),
					},
				}),
			),
		},
	})

	// Static path
	paths.Set("/users/admin", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getAdminUser",
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(200, &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: ptrStr("Success"),
					},
				}),
			),
		},
	})

	doc := openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:   "Test API",
			Version: "1.0.0",
		},
		Paths: paths,
	}

	oasAPI := oas.OAS{T: doc}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Middleware: &oas.Middleware{
			Operations: oas.Operations{
				"getUserById": {
					ValidateRequest: &oas.ValidateRequest{
						Enabled: true,
					},
				},
				// getAdminUser has no ValidateRequest
			},
		},
	})

	api := ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "OAS Path Ordering Benchmark"
		spec.APIID = "oas-path-ordering-benchmark"
		spec.Proxy.ListenPath = "/api/"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
	})[0]

	require.NotNil(b, api)
	require.True(b, api.IsOAS)

	// Create request objects once
	reqParameterized := httptest.NewRequest(http.MethodGet, "/api/users/123", nil)
	reqStatic := httptest.NewRequest(http.MethodGet, "/api/users/admin", nil)

	b.Run("ParameterizedPath", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			ts.TestServerRouter.ServeHTTP(rec, reqParameterized)
			if rec.Code != http.StatusOK {
				b.Fatalf("expected 200, got %d", rec.Code)
			}
		}
	})

	b.Run("StaticPath", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			ts.TestServerRouter.ServeHTTP(rec, reqStatic)
			if rec.Code != http.StatusOK {
				b.Fatalf("expected 200, got %d", rec.Code)
			}
		}
	})
}