package gateway

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
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

func TestAPISpecReleaseCompiledPathConfigSkipsOAS(t *testing.T) {
	version := apidef.VersionInfo{Name: "Default", UseExtendedPaths: true}
	version.ExtendedPaths.Transform = []apidef.TemplateMeta{{Path: "/transform", Method: http.MethodPost}}

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID: "oas-release-skip",
			IsOAS: true,
			ResponseProcessors: []apidef.ResponseProcessor{{
				Name: "header_injector",
			}},
			VersionData: apidef.VersionData{
				NotVersioned: true,
				Versions: map[string]apidef.VersionInfo{
					"Default": version,
				},
			},
		},
	}

	spec.releaseCompiledPathConfig()
	version = spec.VersionData.Versions["Default"]
	if got := len(version.ExtendedPaths.Transform); got != 1 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(oas) transform paths = %d, want 1", got)
	}
	if got := len(spec.ResponseProcessors); got != 1 {
		t.Fatalf("APISpec.releaseCompiledPathConfig(oas) response processors = %d, want 1", got)
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
