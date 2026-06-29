package gateway

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/model"
)

func TestAPISpecReleaseCompiledPathConfigPreservesClassicManagementPayload(t *testing.T) {
	gw := gatewayForAPISpecReleaseTest()
	apiID := "classic-release-payload"
	input := classicAPIDefinitionForReleaseTest(apiID)

	loader := APIDefinitionLoader{Gw: gw}
	spec, err := loader.MakeSpec(&model.MergedAPI{APIDefinition: input}, nil)
	if err != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(%q) error = %v, want nil", apiID, err)
	}
	rewriteMiddleware := &URLRewriteMiddleware{BaseMiddleware: &BaseMiddleware{Spec: spec}}
	if !rewriteMiddleware.EnabledForSpec() {
		t.Fatalf("URLRewriteMiddleware.EnabledForSpec(%q) = false, want true", apiID)
	}

	spec.releaseCompiledPathConfig()
	version := spec.VersionData.Versions["Default"]
	if got := len(version.ExtendedPaths.Transform); got != 0 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(%q) retained transform paths = %d, want 0", apiID, got)
	}
	if got := len(version.ExtendedPaths.URLRewrite); got != 0 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(%q) retained URL rewrite paths = %d, want 0", apiID, got)
	}
	if !spec.URLRewriteEnabled {
		t.Fatalf("APISpec.releaseCompiledPathConfig(%q) URLRewriteEnabled = false, want true", apiID)
	}
	if got := len(spec.ResponseProcessors); got != 0 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(%q) retained response processors = %d, want 0", apiID, got)
	}

	payload, ok := spec.rawAPIDefinitionPayload()
	if !ok {
		t.Fatalf("APISpec.rawAPIDefinitionPayload(%q) ok = false, want true", apiID)
	}
	rawDef := decodeRawAPIDefinition(t, payload)
	rawVersion := rawDef.VersionData.Versions["Default"]
	if got := len(rawVersion.ExtendedPaths.Transform); got != 1 {
		t.Fatalf("raw APIDefinition %q transform paths = %d, want 1", apiID, got)
	}
	if got := len(rawVersion.ExtendedPaths.URLRewrite); got != 1 {
		t.Fatalf("raw APIDefinition %q URL rewrite paths = %d, want 1", apiID, got)
	}
	if got := len(rawVersion.ExtendedPaths.TransformHeader); got != 1 {
		t.Fatalf("raw APIDefinition %q transform header paths = %d, want 1", apiID, got)
	}
	if got := len(rawDef.ResponseProcessors); got != 1 {
		t.Fatalf("raw APIDefinition %q response processors = %d, want 1", apiID, got)
	}

	gw.apisByID[apiID] = spec
	obj, code := gw.handleGetAPI(apiID, false)
	if code != http.StatusOK {
		t.Fatalf("Gateway.handleGetAPI(%q) code = %d, want %d", apiID, code, http.StatusOK)
	}
	rawGet, ok := obj.(json.RawMessage)
	if !ok {
		t.Fatalf("Gateway.handleGetAPI(%q) returned %T, want json.RawMessage", apiID, obj)
	}
	getDef := decodeRawAPIDefinition(t, rawGet)
	if got := len(getDef.VersionData.Versions["Default"].ExtendedPaths.Transform); got != 1 {
		t.Fatalf("Gateway.handleGetAPI(%q) transform paths = %d, want 1", apiID, got)
	}
	if got := len(getDef.VersionData.Versions["Default"].ExtendedPaths.URLRewrite); got != 1 {
		t.Fatalf("Gateway.handleGetAPI(%q) URL rewrite paths = %d, want 1", apiID, got)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/apis", nil)
	obj, code = gw.handleGetAPIList(req)
	if code != http.StatusOK {
		t.Fatalf("Gateway.handleGetAPIList() code = %d, want %d", code, http.StatusOK)
	}
	list, ok := obj.([]json.RawMessage)
	if !ok {
		t.Fatalf("Gateway.handleGetAPIList() returned %T, want []json.RawMessage", obj)
	}
	if got := len(list); got != 1 {
		t.Fatalf("Gateway.handleGetAPIList() returned %d APIs, want 1", got)
	}
	listDef := decodeRawAPIDefinition(t, list[0])
	if got := len(listDef.VersionData.Versions["Default"].ExtendedPaths.Transform); got != 1 {
		t.Fatalf("Gateway.handleGetAPIList() transform paths = %d, want 1", got)
	}
	if got := len(listDef.VersionData.Versions["Default"].ExtendedPaths.URLRewrite); got != 1 {
		t.Fatalf("Gateway.handleGetAPIList() URL rewrite paths = %d, want 1", got)
	}
}

func TestAPISpecReleaseCompiledPathConfigKeepsCompiledFeatureEnablement(t *testing.T) {
	gw := gatewayForAPISpecReleaseTest()
	version := apidef.VersionInfo{Name: "Default", UseExtendedPaths: true}
	version.ExtendedPaths.Transform = []apidef.TemplateMeta{{Path: "/transform", Method: http.MethodPost}}

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "compiled-feature-enablement",
			OrgID: "org",
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions: map[string]apidef.VersionInfo{
					"Default": version,
				},
			},
		},
		GlobalConfig: config.Config{EnableAnalytics: true},
		RxPaths: map[string][]URLSpec{
			"Default": {
				{Status: Transformed, metadata: &TransformSpec{}},
				{Status: HeaderInjected, metadata: &apidef.HeaderInjectionMeta{}},
				{Status: RequestSizeLimit, metadata: &apidef.RequestSizeMeta{}},
				{Status: MethodTransformed, metadata: &apidef.MethodTransformMeta{}},
				{Status: RequestTracked, metadata: &apidef.TrackEndpointMeta{}},
				{Status: ValidateJSONRequest, metadata: &apidef.ValidatePathMeta{}},
				{Status: GoPlugin, metadata: &GoPluginMiddleware{}},
				{Status: PersistGraphQL, metadata: &apidef.PersistGraphQLMeta{}},
				{Status: RateLimit, metadata: &apidef.RateLimitMeta{Path: "/rate", Rate: 1, Per: 1}},
				{Status: TransformedResponse, metadata: &TransformSpec{}},
				{Status: HeaderInjectedResponse, metadata: &apidef.HeaderInjectionMeta{}},
				{Status: HardTimeout, metadata: &apidef.HardTimeoutMeta{TimeOut: 1}},
				{Status: CircuitBreaker, metadata: &ExtendedCircuitBreakerMeta{}},
			},
		},
	}

	spec.releaseCompiledPathConfig()
	if got := len(spec.VersionData.Versions["Default"].ExtendedPaths.Transform); got != 0 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(compiled-feature-enablement) retained transform paths = %d, want 0", got)
	}

	base := &BaseMiddleware{Spec: spec, Gw: gw}
	tests := []struct {
		name    string
		enabled func() bool
	}{
		{name: "request transform", enabled: func() bool { return (&TransformMiddleware{base}).EnabledForSpec() }},
		{name: "request header transform", enabled: func() bool { return (&TransformHeaders{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "request size limit", enabled: func() bool { return (&RequestSizeLimitMiddleware{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "method transform", enabled: func() bool { return (&TransformMethod{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "track endpoint", enabled: func() bool { return (&TrackEndpointMiddleware{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "validate json", enabled: func() bool { return (&ValidateJSON{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "go plugin", enabled: func() bool { return (&GoPluginMiddleware{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "persist graphql", enabled: func() bool { return (&PersistGraphQLOperationMiddleware{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "api rate limit", enabled: func() bool { return (&RateLimitForAPI{BaseMiddleware: base}).EnabledForSpec() }},
		{name: "response transform", enabled: func() bool {
			handler := &ResponseTransformMiddleware{BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: gw}}
			return handler.Enabled()
		}},
		{name: "response header transform", enabled: func() bool {
			handler := &HeaderInjector{BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: gw}}
			return handler.Enabled()
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.enabled() {
				t.Fatalf("%s Enabled() = false, want true after APISpec.releaseCompiledPathConfig", tt.name)
			}
		})
	}

	baseFromConstructor := NewBaseMiddleware(gw, spec, nil, nil)
	if !baseFromConstructor.Spec.EnforcedTimeoutEnabled {
		t.Fatal("NewBaseMiddleware(...).Spec.EnforcedTimeoutEnabled = false, want true after APISpec.releaseCompiledPathConfig")
	}
	if !baseFromConstructor.Spec.CircuitBreakerEnabled {
		t.Fatal("NewBaseMiddleware(...).Spec.CircuitBreakerEnabled = false, want true after APISpec.releaseCompiledPathConfig")
	}
}

func TestAPISpecReleaseCompiledPathConfigReleasesEligibleOASRuntimeDocumentState(t *testing.T) {
	_, spec := oasSpecForReleaseTest(t, nil)
	if spec.OAS.Paths == nil || spec.OAS.Paths.Value("/users/{id}") == nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(OAS release test) paths = %#v, want /users/{id}", spec.OAS.Paths)
	}
	if !spec.canReleaseOASDocumentRuntimeState() {
		t.Fatal("APISpec.canReleaseOASDocumentRuntimeState(OAS release test) = false, want true")
	}

	spec.releaseCompiledPathConfig()

	if !spec.oasRuntimeDocumentReleased {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS release test) released = false, want true")
	}
	if spec.OAS.Paths != nil {
		t.Fatalf("APISpec.releaseCompiledPathConfig(OAS release test) paths = %#v, want nil", spec.OAS.Paths)
	}
	if spec.OAS.Info == nil || spec.OAS.Info.Title != "OAS router lazy test" {
		t.Fatalf("APISpec.releaseCompiledPathConfig(OAS release test) info title = %#v, want OAS router lazy test", spec.OAS.Info)
	}
	if spec.OAS.GetTykExtension() == nil {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS release test) Tyk extension = nil, want preserved extension")
	}
}

func TestAPISpecReleaseCompiledPathConfigReleasesEligibleOASOperationMiddleware(t *testing.T) {
	gw, spec := oasSpecForReleaseTest(t, oas.Operations{
		"getUser": {
			IgnoreAuthentication: &oas.Allowance{Enabled: true},
			TransformRequestHeaders: &oas.TransformHeaders{
				Enabled: true,
				Add:     []oas.Header{{Name: "x-test", Value: "true"}},
			},
			URLRewrite: &oas.URLRewrite{
				Enabled:   true,
				Pattern:   "/users/{id}",
				RewriteTo: "/rewritten",
			},
			MockResponse: &oas.MockResponse{
				Enabled: true,
				Code:    http.StatusCreated,
				Body:    `{"mocked":true}`,
			},
		},
	})
	middleware := spec.OAS.GetTykMiddleware()
	if middleware == nil || len(middleware.Operations) != 1 {
		t.Fatalf("APIDefinitionLoader.MakeSpec(OAS operation release test) operations = %d, want 1", oasOperationCount(middleware))
	}
	if !spec.hasCompiledURLStatus(Ignored, HeaderInjected, URLRewrite, OASMockResponse) {
		t.Fatal("APIDefinitionLoader.MakeSpec(OAS operation release test) did not compile expected operation middleware")
	}
	if !spec.canReleaseOASDocumentRuntimeState() {
		t.Fatal("APISpec.canReleaseOASDocumentRuntimeState(OAS operation release test) = false, want true")
	}
	version := spec.VersionData.Versions[oas.Main]
	if got := len(version.ExtendedPaths.URLRewrite); got != 1 {
		t.Fatalf("APIDefinitionLoader.MakeSpec(OAS operation release test) URL rewrite paths = %d, want 1 before release", got)
	}
	if got := len(version.ExtendedPaths.TransformHeader); got != 1 {
		t.Fatalf("APIDefinitionLoader.MakeSpec(OAS operation release test) transform header paths = %d, want 1 before release", got)
	}

	spec.releaseCompiledPathConfig()

	middleware = spec.OAS.GetTykMiddleware()
	if middleware == nil {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS operation release test) middleware = nil, want preserved middleware shell")
	}
	if got := len(middleware.Operations); got != 0 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(OAS operation release test) retained operations = %d, want 0", got)
	}
	if !spec.hasCompiledURLStatus(Ignored, HeaderInjected, URLRewrite, OASMockResponse) {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS operation release test) lost compiled operation middleware")
	}
	if !spec.hasActiveMock() {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS operation release test) hasActiveMock = false, want true from compiled metadata")
	}
	version = spec.VersionData.Versions[oas.Main]
	if got := len(version.ExtendedPaths.URLRewrite); got != 0 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(OAS operation release test) retained URL rewrite paths = %d, want 0", got)
	}
	if got := len(version.ExtendedPaths.TransformHeader); got != 0 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(OAS operation release test) retained transform header paths = %d, want 0", got)
	}

	mockMw := newMockResponseMiddleware(NewBaseMiddleware(gw, spec, nil, nil))
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oas-release/users/123", nil)
	if err, _ := mockMw.ProcessRequest(rw, req, nil); err != nil {
		t.Fatalf("mockResponseMiddleware.ProcessRequest(OAS operation release test) error = %v, want nil", err)
	}
	if rw.Code != http.StatusCreated {
		t.Fatalf("mockResponseMiddleware.ProcessRequest(OAS operation release test) code = %d, want %d", rw.Code, http.StatusCreated)
	}

	gw.apisByID[spec.APIID] = spec
	obj, code := gw.handleGetAPI(spec.APIID, true)
	if code != http.StatusOK {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS operation release test) code = %d, want %d", spec.APIID, code, http.StatusOK)
	}
	oasDoc, ok := obj.(*oas.OAS)
	if !ok {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS operation release test) returned %T, want *oas.OAS", spec.APIID, obj)
	}
	managementMiddleware := oasDoc.GetTykMiddleware()
	if managementMiddleware == nil || len(managementMiddleware.Operations) != 1 {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS operation release test) operations = %d, want 1", spec.APIID, oasOperationCount(managementMiddleware))
	}
	if got := managementMiddleware.Operations["getUser"]; got == nil || got.URLRewrite == nil || got.TransformRequestHeaders == nil || got.IgnoreAuthentication == nil || got.MockResponse == nil {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS operation release test) operation = %#v, want rewrite, header transform, ignore auth, and mock response", spec.APIID, got)
	}
}

func TestAPISpecReleaseCompiledPathConfigReleasesEligibleOASGlobalMiddleware(t *testing.T) {
	gw, spec := oasSpecWithGlobalMiddlewareForReleaseTest(t)
	middleware := spec.OAS.GetTykMiddleware()
	if middleware == nil || middleware.Global == nil {
		t.Fatal("APIDefinitionLoader.MakeSpec(OAS global release test) middleware.global = nil, want configured global middleware")
	}
	if !(&TransformHeaders{BaseMiddleware: NewBaseMiddleware(gw, spec, nil, nil)}).EnabledForSpec() {
		t.Fatal("TransformHeaders.EnabledForSpec(OAS global release test) = false, want true from extracted classic fields")
	}
	if !(&HeaderInjector{BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: gw}}).Enabled() {
		t.Fatal("HeaderInjector.Enabled(OAS global release test) = false, want true from extracted classic fields")
	}
	if !spec.canReleaseOASDocumentRuntimeState() {
		t.Fatal("APISpec.canReleaseOASDocumentRuntimeState(OAS global release test) = false, want true")
	}

	spec.releaseCompiledPathConfig()

	middleware = spec.OAS.GetTykMiddleware()
	if middleware == nil {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS global release test) middleware = nil, want preserved middleware shell")
	}
	if middleware.Global != nil {
		t.Fatalf("APISpec.releaseCompiledPathConfig(OAS global release test) middleware.global = %#v, want nil", middleware.Global)
	}
	if !spec.hasOASGlobalHeaderRuntimeFields() {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS global release test) lost extracted classic global header fields")
	}

	req := httptest.NewRequest(http.MethodGet, "/oas-release/users/123", nil)
	headerMiddleware := &TransformHeaders{BaseMiddleware: NewBaseMiddleware(gw, spec, nil, nil)}
	if err, code := headerMiddleware.ProcessRequest(httptest.NewRecorder(), req, nil); err != nil || code != http.StatusOK {
		t.Fatalf("TransformHeaders.ProcessRequest(OAS global release test) error/code = %v/%d, want nil/%d", err, code, http.StatusOK)
	}
	if got := req.Header.Get("X-OAS-Global-Request"); got != "request-ok" {
		t.Fatalf("TransformHeaders.ProcessRequest(OAS global release test) header = %q, want %q", got, "request-ok")
	}

	res := &http.Response{Header: make(http.Header)}
	responseHandler := &HeaderInjector{BaseTykResponseHandler: BaseTykResponseHandler{Spec: spec, Gw: gw}}
	if err := responseHandler.HandleResponse(httptest.NewRecorder(), res, req, nil); err != nil {
		t.Fatalf("HeaderInjector.HandleResponse(OAS global release test) error = %v, want nil", err)
	}
	if got := res.Header.Get("X-OAS-Global-Response"); got != "response-ok" {
		t.Fatalf("HeaderInjector.HandleResponse(OAS global release test) header = %q, want %q", got, "response-ok")
	}

	gw.apisByID[spec.APIID] = spec
	obj, code := gw.handleGetAPI(spec.APIID, true)
	if code != http.StatusOK {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS global release test) code = %d, want %d", spec.APIID, code, http.StatusOK)
	}
	oasDoc, ok := obj.(*oas.OAS)
	if !ok {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS global release test) returned %T, want *oas.OAS", spec.APIID, obj)
	}
	managementMiddleware := oasDoc.GetTykMiddleware()
	if managementMiddleware == nil || managementMiddleware.Global == nil || managementMiddleware.Global.TransformRequestHeaders == nil || managementMiddleware.Global.TransformResponseHeaders == nil {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS global release test) global middleware = %#v, want request and response headers reconstructed", spec.APIID, managementMiddleware)
	}
}

func TestAPISpecReleaseCompiledPathConfigPreservesOASManagementPayload(t *testing.T) {
	gw, spec := oasSpecForReleaseTest(t, nil)
	spec.releaseCompiledPathConfig()
	gw.apisByID[spec.APIID] = spec

	obj, code := gw.handleGetAPI(spec.APIID, true)
	if code != http.StatusOK {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS) code = %d, want %d", spec.APIID, code, http.StatusOK)
	}
	oasDoc, ok := obj.(*oas.OAS)
	if !ok {
		t.Fatalf("Gateway.handleGetAPI(%q, OAS) returned %T, want *oas.OAS", spec.APIID, obj)
	}
	assertFullOASReleaseTestDocument(t, "Gateway.handleGetAPI", oasDoc)

	obj, code = gw.handleGetOASList(isOASNotMCP, false)
	if code != http.StatusOK {
		t.Fatalf("Gateway.handleGetOASList(OAS release test) code = %d, want %d", code, http.StatusOK)
	}
	oasList, ok := obj.([]oas.OAS)
	if !ok {
		t.Fatalf("Gateway.handleGetOASList(OAS release test) returned %T, want []oas.OAS", obj)
	}
	if got := len(oasList); got != 1 {
		t.Fatalf("Gateway.handleGetOASList(OAS release test) len = %d, want 1", got)
	}
	assertFullOASReleaseTestDocument(t, "Gateway.handleGetOASList", &oasList[0])
}

func TestAPISpecReleaseCompiledPathConfigKeepsOASWhenRuntimeDocumentConsumerExists(t *testing.T) {
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
			_, spec := oasSpecForReleaseTest(t, oas.Operations{"getUser": tt.operation})
			if spec.canReleaseOASDocumentRuntimeState() {
				t.Fatalf("APISpec.canReleaseOASDocumentRuntimeState(%s) = true, want false", tt.name)
			}

			spec.releaseCompiledPathConfig()

			if spec.OAS.Paths == nil || spec.OAS.Paths.Value("/users/{id}") == nil {
				t.Fatalf("APISpec.releaseCompiledPathConfig(%s) paths = %#v, want retained /users/{id}", tt.name, spec.OAS.Paths)
			}
			if spec.oasRuntimeDocumentReleased {
				t.Fatalf("APISpec.releaseCompiledPathConfig(%s) released = true, want false", tt.name)
			}
		})
	}
}

func TestAPISpecReleaseCompiledPathConfigKeepsOASWhenRequestContextConsumerConfigured(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*APISpec)
	}{
		{
			name: "custom plugin",
			mutate: func(spec *APISpec) {
				spec.CustomMiddleware.Driver = apidef.GoPluginDriver
				spec.CustomMiddleware.Pre = []apidef.MiddlewareDefinition{{Name: "PreHook"}}
			},
		},
		{
			name: "OAS authentication",
			mutate: func(spec *APISpec) {
				spec.OAS.GetTykExtension().Server.Authentication = &oas.Authentication{Enabled: true}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, spec := oasSpecForReleaseTest(t, nil)
			tt.mutate(spec)
			if spec.canReleaseOASDocumentRuntimeState() {
				t.Fatalf("APISpec.canReleaseOASDocumentRuntimeState(%s) = true, want false", tt.name)
			}

			spec.releaseCompiledPathConfig()

			if spec.OAS.Paths == nil || spec.OAS.Paths.Value("/users/{id}") == nil {
				t.Fatalf("APISpec.releaseCompiledPathConfig(%s) paths = %#v, want retained /users/{id}", tt.name, spec.OAS.Paths)
			}
			if spec.oasRuntimeDocumentReleased {
				t.Fatalf("APISpec.releaseCompiledPathConfig(%s) released = true, want false", tt.name)
			}
		})
	}
}

func TestAPISpecReleaseCompiledPathConfigKeepsOASWhenVersioningConfigured(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*APISpec)
	}{
		{
			name: "base versioning enabled",
			mutate: func(spec *APISpec) {
				spec.VersionDefinition.Enabled = true
			},
		},
		{
			name: "child base ID",
			mutate: func(spec *APISpec) {
				spec.VersionDefinition.BaseID = "base-api-id"
			},
		},
		{
			name: "version map",
			mutate: func(spec *APISpec) {
				spec.VersionDefinition.Versions = map[string]string{"v1": spec.APIID}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, spec := oasSpecForReleaseTest(t, nil)
			tt.mutate(spec)
			if spec.canReleaseOASDocumentRuntimeState() {
				t.Fatalf("APISpec.canReleaseOASDocumentRuntimeState(%s) = true, want false", tt.name)
			}

			spec.releaseCompiledPathConfig()

			if spec.OAS.Paths == nil || spec.OAS.Paths.Value("/users/{id}") == nil {
				t.Fatalf("APISpec.releaseCompiledPathConfig(%s) paths = %#v, want retained /users/{id}", tt.name, spec.OAS.Paths)
			}
			if spec.oasRuntimeDocumentReleased {
				t.Fatalf("APISpec.releaseCompiledPathConfig(%s) released = true, want false", tt.name)
			}
		})
	}
}

func TestAPISpecReleaseCompiledPathConfigSkipsOASWithoutPaths(t *testing.T) {
	_, spec := oasSpecForReleaseTest(t, nil)
	spec.OAS.Paths = nil
	if spec.canReleaseOASDocumentRuntimeState() {
		t.Fatal("APISpec.canReleaseOASDocumentRuntimeState(OAS without paths) = true, want false")
	}

	spec.releaseCompiledPathConfig()

	if spec.oasRuntimeDocumentReleased {
		t.Fatal("APISpec.releaseCompiledPathConfig(OAS without paths) released = true, want false")
	}
}

func gatewayForAPISpecReleaseTest() *Gateway {
	gw := &Gateway{
		apisByID: map[string]*APISpec{},
	}
	gw.SetConfig(config.Config{
		DisableDashboardZeroConf: true,
		NodeSecret:               "test-secret",
	}, true)
	return gw
}

func oasSpecForReleaseTest(t *testing.T, operations oas.Operations) (*Gateway, *APISpec) {
	t.Helper()

	gw := newGatewayForOASRouterLazyTest()
	spec, err := (APIDefinitionLoader{Gw: gw}).MakeSpec(
		newOASRouterLazyMergedAPI(t, "/oas-release/", operations),
		nil,
	)
	if err != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(OAS release test) error = %v, want nil", err)
	}
	return gw, spec
}

func oasSpecWithGlobalMiddlewareForReleaseTest(t *testing.T) (*Gateway, *APISpec) {
	t.Helper()

	gw := newGatewayForOASRouterLazyTest()
	merged := newOASRouterLazyMergedAPI(t, "/oas-release/", nil)
	tykExt := merged.OAS.GetTykExtension()
	if tykExt.Middleware == nil {
		tykExt.Middleware = &oas.Middleware{}
	}
	tykExt.Middleware.Global = &oas.Global{
		TransformRequestHeaders: &oas.TransformHeaders{
			Enabled: true,
			Add: []oas.Header{
				{Name: "X-OAS-Global-Request", Value: "request-ok"},
			},
		},
		TransformResponseHeaders: &oas.TransformHeaders{
			Enabled: true,
			Add: []oas.Header{
				{Name: "X-OAS-Global-Response", Value: "response-ok"},
			},
		},
	}
	merged.OAS.SetTykExtension(tykExt)
	merged.OAS.ExtractTo(merged.APIDefinition)
	merged.APIDefinition.APIID = "oas-router-lazy"
	merged.APIDefinition.Name = "OAS router lazy test"
	merged.APIDefinition.IsOAS = true
	merged.APIDefinition.UseKeylessAccess = true
	merged.APIDefinition.VersionData.NotVersioned = true
	merged.APIDefinition.VersionData.DefaultVersion = oas.Main

	spec, err := (APIDefinitionLoader{Gw: gw}).MakeSpec(merged, nil)
	if err != nil {
		t.Fatalf("APIDefinitionLoader.MakeSpec(OAS global release test) error = %v, want nil", err)
	}
	return gw, spec
}

func (a *APISpec) hasOASGlobalHeaderRuntimeFields() bool {
	if a == nil || a.APIDefinition == nil {
		return false
	}
	vInfo, ok := a.VersionData.Versions[oas.Main]
	if !ok {
		return false
	}
	return vInfo.GlobalHeaders["X-OAS-Global-Request"] == "request-ok" &&
		vInfo.GlobalResponseHeaders["X-OAS-Global-Response"] == "response-ok"
}

func assertFullOASReleaseTestDocument(t *testing.T, caller string, oasDoc *oas.OAS) {
	t.Helper()

	if oasDoc.Paths == nil || oasDoc.Paths.Value("/users/{id}") == nil {
		t.Fatalf("%s(OAS release test) paths = %#v, want /users/{id}", caller, oasDoc.Paths)
	}
	if oasDoc.Info == nil || oasDoc.Info.Title != "OAS router lazy test" {
		t.Fatalf("%s(OAS release test) info title = %#v, want OAS router lazy test", caller, oasDoc.Info)
	}
	tykExt := oasDoc.GetTykExtension()
	if tykExt == nil {
		t.Fatalf("%s(OAS release test) Tyk extension = nil, want extension", caller)
	}
	if got := tykExt.Server.ListenPath.Value; got != "/oas-release/" {
		t.Fatalf("%s(OAS release test) listen path = %q, want %q", caller, got, "/oas-release/")
	}
}

func classicAPIDefinitionForReleaseTest(apiID string) *apidef.APIDefinition {
	templateSource := base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`))
	version := apidef.VersionInfo{
		Name:             "Default",
		UseExtendedPaths: true,
	}
	version.ExtendedPaths.Transform = []apidef.TemplateMeta{{
		Path:   "/transform",
		Method: http.MethodPost,
		TemplateData: apidef.TemplateData{
			Input:          apidef.RequestJSON,
			Mode:           apidef.UseBlob,
			TemplateSource: templateSource,
		},
	}}
	version.ExtendedPaths.URLRewrite = []apidef.URLRewriteMeta{{
		Path:         "/rewrite",
		Method:       http.MethodGet,
		MatchPattern: "/rewrite",
		RewriteTo:    "/rewritten",
	}}
	version.ExtendedPaths.TransformHeader = []apidef.HeaderInjectionMeta{{
		Path:       "/headers",
		Method:     http.MethodGet,
		AddHeaders: map[string]string{"x-test": "true"},
	}}

	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = apiID
		spec.Name = apiID
		spec.UseKeylessAccess = true
		spec.ResponseProcessors = []apidef.ResponseProcessor{{
			Name: "header_injector",
		}}
		spec.VersionData = apidef.VersionData{
			NotVersioned:   true,
			DefaultVersion: "Default",
			Versions: map[string]apidef.VersionInfo{
				"Default": version,
			},
		}
	})[0]

	return spec.APIDefinition
}

func decodeRawAPIDefinition(t *testing.T, payload json.RawMessage) apidef.APIDefinition {
	t.Helper()

	var def apidef.APIDefinition
	if err := json.Unmarshal(payload, &def); err != nil {
		t.Fatalf("json.Unmarshal(APIDefinition) error = %v, want nil", err)
	}
	return def
}
