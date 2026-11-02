package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/mcp"
	"github.com/TykTechnologies/tyk/regexp"
)

func TestURLSpec_matchesPath_ListenPathMatching(t *testing.T) {
	mcp.RegisterVEMPrefixes()

	newAPI := func(isOAS bool, listenPath string, allowUnsafe bool) *APISpec {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: listenPath, StripListenPath: true},
		}}
		spec.IsOAS = isOAS
		spec.GlobalConfig = config.Config{AllowUnsafeListenPathMatching: allowUnsafe}
		return spec
	}

	newURLSpec := func(status URLStatus, path string) *URLSpec {
		return &URLSpec{
			Status: status,
			spec:   regexp.MustCompile(httputil.PreparePathRegexp(path, true, true)),
		}
	}

	testCases := []struct {
		name        string
		listenPath  string
		status      URLStatus
		endpoint    string
		reqPath     string
		allowUnsafe bool
		want        bool
	}{
		{
			name:       "upstream path matches the endpoint",
			listenPath: "/employees", status: WhiteList, endpoint: "/static",
			reqPath: "/employees/static", want: true,
		},
		{
			name:       "endpoint that includes the listen path matches the upstream path",
			listenPath: "/employees", status: WhiteList, endpoint: "/employees/static",
			reqPath: "/employees/employees/static", want: true,
		},
		{
			name:       "endpoint that includes the listen path does not match the full request path",
			listenPath: "/employees", status: WhiteList, endpoint: "/employees/static",
			reqPath: "/employees/static", want: false,
		},
		{
			name:       "parameterised endpoint does not match the full request path",
			listenPath: "/employees", status: WhiteList, endpoint: "/employees/{id}",
			reqPath: "/employees/qzxjklmwvbnpfgh", want: false,
		},
		{
			name:       "parameterised endpoint matches the upstream path",
			listenPath: "/employees", status: WhiteList, endpoint: "/employees/{id}",
			reqPath: "/employees/employees/123", want: true,
		},
		{
			name:       "endpoint-level middleware does not match the full request path",
			listenPath: "/employees", status: HeaderInjected, endpoint: "/employees/static",
			reqPath: "/employees/static", want: false,
		},
		{
			name:       "allow_unsafe_listen_path_matching matches the full request path",
			listenPath: "/employees", status: WhiteList, endpoint: "/employees/static",
			reqPath: "/employees/static", allowUnsafe: true, want: true,
		},
		{
			name:       "block list still matches the full request path",
			listenPath: "/employees", status: BlackList, endpoint: "/employees/static",
			reqPath: "/employees/static", want: true,
		},
		{
			name:       "internal endpoint still matches the full request path",
			listenPath: "/employees", status: Internal, endpoint: "/employees/static",
			reqPath: "/employees/static", want: true,
		},
		{
			// /mcp is a text prefix of the VEM path, so stripping it mangles the path.
			name:       "VEM path matches the full request path",
			listenPath: "/mcp", status: WhiteList, endpoint: mcp.ToolPrefix + "get-weather",
			reqPath: mcp.ToolPrefix + "get-weather", want: true,
		},
	}

	for _, isOAS := range []bool{false, true} {
		apiType := "classic"
		if isOAS {
			apiType = "oas"
		}

		for _, tc := range testCases {
			t.Run(apiType+"/"+tc.name, func(t *testing.T) {
				api := newAPI(isOAS, tc.listenPath, tc.allowUnsafe)
				urlSpec := newURLSpec(tc.status, tc.endpoint)

				assert.Equal(t, tc.want, urlSpec.matchesPath(tc.reqPath, api))
			})
		}
	}
}

func TestURLSpec_matchesPath_ListenPathNotStripped(t *testing.T) {
	newAPI := func(isOAS bool) *APISpec {
		spec := &APISpec{APIDefinition: &apidef.APIDefinition{
			Proxy: apidef.ProxyConfig{ListenPath: "/employees", StripListenPath: false},
		}}
		spec.IsOAS = isOAS
		return spec
	}

	urlSpec := &URLSpec{
		Status: WhiteList,
		spec:   regexp.MustCompile(httputil.PreparePathRegexp("/employees/static", true, true)),
	}

	// The full request path is proxied upstream, so Tyk Classic matches it.
	assert.True(t, urlSpec.matchesPath("/employees/static", newAPI(false)))
	// Tyk OAS endpoint paths are relative to the listen path.
	assert.False(t, urlSpec.matchesPath("/employees/static", newAPI(true)))
	assert.True(t, urlSpec.matchesPath("/employees/employees/static", newAPI(true)))
}
