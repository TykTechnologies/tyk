package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/model"
)

func TestMakeSpecSkipsOASRouterForOperationMiddleware(t *testing.T) {
	gw := newGatewayForOASRouterLazyTest()
	merged := newOASRouterLazyMergedAPI(t, "/oas-router-lazy/", oas.Operations{
		"getUser": {
			IgnoreAuthentication: &oas.Allowance{Enabled: true},
		},
	})

	spec, err := (APIDefinitionLoader{Gw: gw}).MakeSpec(merged, nil)
	if err != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(operation middleware) error = %v, want nil", err)
	}
	if spec.oasRouter != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(operation middleware) initialized oasRouter, want nil")
	}

	var pathCount int
	for _, paths := range spec.RxPaths {
		pathCount += len(paths)
	}
	if pathCount == 0 {
		t.Fatalf("APIDefinitionLoader.MakeSpec(operation middleware) compiled path count = 0, want non-zero")
	}
}

func TestFindRouteForOASPathDoesNotRequireRouterForNormalListenPath(t *testing.T) {
	gw := newGatewayForOASRouterLazyTest()
	merged := newOASRouterLazyMergedAPI(t, "/oas-router-lazy/", oas.Operations{
		"getUser": {
			ValidateRequest: &oas.ValidateRequest{Enabled: true},
		},
	})

	spec, err := (APIDefinitionLoader{Gw: gw}).MakeSpec(merged, nil)
	if err != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(validate request) error = %v, want nil", err)
	}
	if spec.oasRouter != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(validate request) initialized oasRouter for normal listen path, want nil")
	}

	route, params, err := spec.findRouteForOASPath("/users/{id}", http.MethodGet, "/users/123", "/oas-router-lazy/users/123")
	if err != nil {
		t.Fatalf("APISpec.findRouteForOASPath(/users/{id}, GET) error = %v, want nil", err)
	}
	if route == nil || route.Operation == nil {
		t.Fatalf("APISpec.findRouteForOASPath(/users/{id}, GET) route = %#v, want operation route", route)
	}
	if got := route.Operation.OperationID; got != "getUser" {
		t.Fatalf("APISpec.findRouteForOASPath(/users/{id}, GET) operationID = %q, want %q", got, "getUser")
	}
	if got := params["id"]; got != "123" {
		t.Fatalf("APISpec.findRouteForOASPath(/users/{id}, GET) path param id = %q, want %q", got, "123")
	}
}

func TestFindRouteForOASPathPreservesMigratedValidateJSONSchema(t *testing.T) {
	input := BuildAPI(func(spec *APISpec) {
		spec.Name = "migrated validate JSON API"
		spec.Proxy.ListenPath = "/listen/"
		spec.Proxy.StripListenPath = true
		spec.ConfigDataDisabled = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.ValidateJSON = []apidef.ValidatePathMeta{{
				Method: http.MethodPost,
				Path:   "/post",
				Schema: map[string]any{
					"required": []string{"name"},
				},
				ErrorResponseCode: http.StatusTeapot,
			}}
		})
	})[0]

	migratedAPI, _, err := oas.MigrateAndFillOAS(input.APIDefinition)
	if err != nil {
		t.Fatalf("oas.MigrateAndFillOAS(validate JSON API) error = %v, want nil", err)
	}

	spec, err := (APIDefinitionLoader{Gw: newGatewayForOASRouterLazyTest()}).MakeSpec(&model.MergedAPI{
		APIDefinition: migratedAPI.Classic,
		OAS:           migratedAPI.OAS,
	}, nil)
	if err != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(migrated validate JSON API) error = %v, want nil", err)
	}
	if spec.oasRouter != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(migrated validate JSON API) initialized oasRouter, want nil")
	}

	var validateSpec *URLSpec
	for _, paths := range spec.RxPaths {
		for i := range paths {
			if paths[i].Status == OASValidateRequest {
				validateSpec = &paths[i]
				break
			}
		}
	}
	if validateSpec == nil {
		t.Fatal("APIDefinitionLoader.MakeSpec(migrated validate JSON API) OASValidateRequest URLSpec = nil, want compiled URLSpec")
	}

	validateMeta, ok := validateSpec.oasValidateRequestRuntimeMeta()
	if !ok || validateMeta == nil {
		t.Fatal("OASValidateRequest URLSpec runtime metadata = nil, want validate-request metadata")
	}

	route, _, err := spec.findRouteForOASPath(validateMeta.Path, validateMeta.Method, "/post", "/listen/post")
	if err != nil {
		t.Fatalf("APISpec.findRouteForOASPath(%q, %q) error = %v, want nil", validateMeta.Path, validateMeta.Method, err)
	}
	if route.Operation == nil || route.Operation.RequestBody == nil || route.Operation.RequestBody.Value == nil {
		t.Fatalf("APISpec.findRouteForOASPath(%q, %q) request body = %#v, want migrated request body", validateMeta.Path, validateMeta.Method, route.Operation)
	}
}

func TestLoadedMigratedValidateRequestMatchesWithoutOASRouter(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	input := BuildAPI(func(spec *APISpec) {
		spec.Name = "loaded migrated validate JSON API"
		spec.Proxy.ListenPath = "/listen/"
		spec.Proxy.StripListenPath = true
		spec.ConfigDataDisabled = true
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.ExtendedPaths.ValidateJSON = []apidef.ValidatePathMeta{{
				Method: http.MethodPost,
				Path:   "/post",
				Schema: map[string]any{
					"required": []string{"name"},
				},
				ErrorResponseCode: http.StatusTeapot,
			}}
		})
	})[0]

	migratedAPI, _, err := oas.MigrateAndFillOAS(input.APIDefinition)
	if err != nil {
		t.Fatalf("oas.MigrateAndFillOAS(loaded validate JSON API) error = %v, want nil", err)
	}
	migratedMiddleware := migratedAPI.OAS.GetTykMiddleware()
	if migratedMiddleware == nil || len(migratedMiddleware.Operations) == 0 {
		t.Fatalf("oas.MigrateAndFillOAS(loaded validate JSON API) middleware operations = %d, want non-zero", oasOperationCount(migratedMiddleware))
	}

	ts.Gw.LoadAPI(&APISpec{APIDefinition: migratedAPI.Classic, OAS: *migratedAPI.OAS})
	loaded := ts.Gw.getApiSpec(input.APIID)
	if loaded == nil {
		t.Fatalf("Gateway.getApiSpec(%q) = nil, want loaded migrated API", input.APIID)
	}
	if loaded.oasRouter != nil {
		t.Fatalf("Gateway.getApiSpec(%q).oasRouter initialized for normal listen path, want nil", input.APIID)
	}

	mw := &ValidateRequest{BaseMiddleware: &BaseMiddleware{Spec: loaded, Gw: ts.Gw}}
	if !mw.EnabledForSpec() {
		t.Fatalf("ValidateRequest.EnabledForSpec(%q) = false, want true; is_oas=%v extension=%v operations=%d",
			input.APIID, loaded.IsOAS, loaded.OAS.GetTykExtension() != nil, oasOperationCount(loaded.OAS.GetTykMiddleware()))
	}

	req := httptest.NewRequest(http.MethodPost, "/listen/post", strings.NewReader(`{"age":27}`))
	req.Header.Set("Content-Type", "application/json")
	versionInfo, status := loaded.Version(req)
	if status != StatusOk {
		t.Fatalf("APISpec.Version(/listen/post) status = %q, want %q", status, StatusOk)
	}

	urlSpec, found := loaded.FindSpecMatchesStatus(req, loaded.RxPaths[versionInfo.Name], OASValidateRequest)
	if !found || urlSpec == nil {
		t.Fatalf("APISpec.FindSpecMatchesStatus(/listen/post, OASValidateRequest) found = %v, spec = %#v, want match", found, urlSpec)
	}

	err, code := mw.ProcessRequest(httptest.NewRecorder(), req, nil)
	if err == nil || code != http.StatusTeapot {
		t.Fatalf("ValidateRequest.ProcessRequest(/listen/post invalid body) = (%v, %d), want error and %d", err, code, http.StatusTeapot)
	}
}

func TestMakeSpecBuildsOASRouterForMuxTemplateRouteLookup(t *testing.T) {
	tests := []struct {
		name      string
		operation *oas.Operation
	}{
		{
			name: "validate request",
			operation: &oas.Operation{
				ValidateRequest: &oas.ValidateRequest{Enabled: true},
			},
		},
		{
			name: "mock from OAS examples",
			operation: &oas.Operation{
				MockResponse: &oas.MockResponse{
					Enabled:         true,
					FromOASExamples: &oas.FromOASExamples{Enabled: true},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newGatewayForOASRouterLazyTest()
			merged := newOASRouterLazyMergedAPI(t, "/oas-router-lazy/{tenant}/", oas.Operations{
				"getUser": tt.operation,
			})

			spec, err := (APIDefinitionLoader{Gw: gw}).MakeSpec(merged, nil)
			if err != nil {
				t.Fatalf("APIDefinitionLoader.MakeSpec(%s) error = %v, want nil", tt.name, err)
			}
			if spec.oasRouter == nil {
				t.Fatalf("APIDefinitionLoader.MakeSpec(%s) oasRouter = nil, want initialized router", tt.name)
			}
		})
	}
}

func newGatewayForOASRouterLazyTest() *Gateway {
	return NewGateway(config.Config{
		UseDBAppConfigs:          false,
		DisableDashboardZeroConf: true,
		NodeSecret:               "test-secret",
	}, context.Background())
}

func oasOperationCount(middleware *oas.Middleware) int {
	if middleware == nil {
		return 0
	}
	return len(middleware.Operations)
}

func newOASRouterLazyMergedAPI(t *testing.T, listenPath string, operations oas.Operations) *model.MergedAPI {
	t.Helper()

	paths := openapi3.NewPaths()
	paths.Set("/users/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getUser",
			Parameters: openapi3.Parameters{
				{
					Value: &openapi3.Parameter{
						Name:     "id",
						In:       "path",
						Required: true,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
						},
					},
				},
			},
			Responses: openapi3.NewResponses(
				openapi3.WithStatus(http.StatusOK, &openapi3.ResponseRef{
					Value: &openapi3.Response{Description: oasRouterLazyStringPtr("ok")},
				}),
			),
		},
	})

	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "OAS router lazy test",
				Version: "1.0.0",
			},
			Paths: paths,
		},
	}
	oasAPI.SetTykExtension(&oas.XTykAPIGateway{
		Info: oas.Info{
			ID:   "oas-router-lazy",
			Name: "OAS router lazy test",
			State: oas.State{
				Active: true,
			},
		},
		Upstream: oas.Upstream{URL: TestHttpAny},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: listenPath,
				Strip: true,
			},
		},
		Middleware: &oas.Middleware{Operations: operations},
	})

	var def apidef.APIDefinition
	oasAPI.ExtractTo(&def)
	def.APIID = "oas-router-lazy"
	def.Name = "OAS router lazy test"
	def.IsOAS = true
	def.UseKeylessAccess = true
	def.Proxy.ListenPath = listenPath
	def.VersionData.NotVersioned = true
	def.VersionData.DefaultVersion = oas.Main
	version := def.VersionData.Versions[oas.Main]
	version.Name = oas.Main
	version.UseExtendedPaths = true
	def.VersionData.Versions = map[string]apidef.VersionInfo{
		oas.Main: version,
	}

	return &model.MergedAPI{
		APIDefinition: &def,
		OAS:           &oasAPI,
	}
}

func oasRouterLazyStringPtr(s string) *string {
	return &s
}
