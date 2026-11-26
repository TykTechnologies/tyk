package gateway

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

func buildOASAPIWithPaths(listenPath string, strip bool, ops oas.Operations, paths map[string]*openapi3.PathItem) *APISpec {
	p := openapi3.NewPaths()
	for k, v := range paths {
		p.Set(k, v)
	}

	spec := BuildOASAPI(func(oasDef *oas.OAS) {
		oasDef.Paths = p
		ext := oasDef.GetTykExtension()
		ext.Info.State.Active = true
		ext.Server.ListenPath = oas.ListenPath{Value: listenPath, Strip: strip}
		ext.Middleware = &oas.Middleware{Operations: ops}
	})[0]
	spec.UseKeylessAccess = true

	return spec
}

func integerIDOperation(id string) *openapi3.Operation {
	return &openapi3.Operation{
		OperationID: id,
		Parameters:  openapi3.Parameters{pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}})},
		Responses:   oasResponse200(),
	}
}

// employeesPaths repeats the listen path /employees inside the OAS paths, as
// reported in TT-18034.
func employeesPaths() map[string]*openapi3.PathItem {
	return map[string]*openapi3.PathItem{
		"/employees/static": {Get: &openapi3.Operation{OperationID: "getStatic", Responses: oasResponse200()}},
		"/employees/{id}":   {Get: integerIDOperation("getById")},
	}
}

func usersPaths() map[string]*openapi3.PathItem {
	return map[string]*openapi3.PathItem{"/users/{id}": {Get: integerIDOperation("getUser")}}
}

func allowAndValidate() *oas.Operation {
	return &oas.Operation{
		Allow:           &oas.Allowance{Enabled: true},
		ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: http.StatusUnprocessableEntity},
	}
}

func buildEmployeesOASAPI(strip bool) *APISpec {
	return buildOASAPIWithPaths("/employees", strip, oas.Operations{
		"getStatic": allowAndValidate(),
		"getById":   allowAndValidate(),
	}, employeesPaths())
}

func TestOASAllowList_ListenPathPrefixOfEndpoints(t *testing.T) {
	t.Run("only the declared operation is forwarded", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.LoadAPI(buildEmployeesOASAPI(true))

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/employees/123", Code: http.StatusOK, BodyMatch: `"Url":"/employees/123"`},
			{Path: "/employees/employees/abc", Code: http.StatusUnprocessableEntity},
			{Path: "/employees/static", Code: http.StatusForbidden},
			{Path: "/employees/hello_world", Code: http.StatusForbidden},
			{Path: "/employees/foo/bar", Code: http.StatusForbidden},
			{Path: "/employees/anything/employees/static", Code: http.StatusForbidden},
			{Path: "/employees/employees/static/extra", Code: http.StatusForbidden},
			{Path: "/employees/employees/123/extra", Code: http.StatusForbidden},
		}...)
	})

	t.Run("allow_unsafe_listen_path_matching restores the full URL fallback", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.AllowUnsafeListenPathMatching = true
		})
		defer ts.Close()

		ts.Gw.LoadAPI(buildEmployeesOASAPI(true))

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/employees/abc", Code: http.StatusUnprocessableEntity},
			{Path: "/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/static"`},
			{Path: "/employees/hello_world", Code: http.StatusOK, BodyMatch: `"Url":"/hello_world"`},
			{Path: "/employees/foo/bar", Code: http.StatusOK, BodyMatch: `"Url":"/foo/bar"`},
			{Path: "/employees/anything/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/anything/employees/static"`},
		}...)
	})

	t.Run("strip_listen_path false matches the path relative to the listen path", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.LoadAPI(buildEmployeesOASAPI(false))

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/employees/static"`},
			{Path: "/employees/static", Code: http.StatusForbidden},
		}...)
	})
}

func TestOASAllowList_DeclaredOperationOnly(t *testing.T) {
	t.Run("allow list alone enforces path parameter schemas", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.LoadAPI(buildOASAPIWithPaths("/employees", true, oas.Operations{
			"getUser": {Allow: &oas.Allowance{Enabled: true}},
		}, usersPaths()))

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/users/123", Code: http.StatusOK, BodyMatch: `"Url":"/users/123"`},
			{Path: "/employees/users/abc", Code: http.StatusForbidden},
			{Path: "/employees/users/123/extra", Code: http.StatusForbidden},
		}...)
	})

	t.Run("paths relative to the listen path", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.LoadAPI(buildOASAPIWithPaths("/api", true, oas.Operations{
			"getUser": allowAndValidate(),
		}, usersPaths()))

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/api/users/123", Code: http.StatusOK, BodyMatch: `"Url":"/users/123"`},
			{Path: "/api/users/abc", Code: http.StatusUnprocessableEntity},
			{Path: "/api/other", Code: http.StatusForbidden},
		}...)
	})

	t.Run("strip_listen_path false keeps the listen path upstream", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.LoadAPI(buildOASAPIWithPaths("/employees", false, oas.Operations{
			"getUser": allowAndValidate(),
		}, usersPaths()))

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/users/123", Code: http.StatusOK, BodyMatch: `"Url":"/employees/users/123"`},
			{Path: "/employees/users/abc", Code: http.StatusUnprocessableEntity},
			{Path: "/employees/other", Code: http.StatusForbidden},
		}...)
	})
}

// TestOASIgnoreAuthentication_ListenPathPrefixOfEndpoints: the full URL
// fallback also matched ignoreAuthentication, letting an unauthenticated
// request reach an undeclared upstream path.
func TestOASIgnoreAuthentication_ListenPathPrefixOfEndpoints(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	spec := buildOASAPIWithPaths("/employees", true, oas.Operations{
		"getStatic": {IgnoreAuthentication: &oas.Allowance{Enabled: true}},
	}, employeesPaths())
	spec.UseKeylessAccess = false
	spec.UseStandardAuth = true
	spec.AuthConfigs = map[string]apidef.AuthConfig{apidef.AuthTokenType: {AuthHeaderName: "Authorization"}}
	ts.Gw.LoadAPI(spec)

	_, _ = ts.Run(t, []test.TestCase{
		{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
		{Path: "/employees/static", Code: http.StatusUnauthorized},
		{Path: "/employees/employees/static/extra", Code: http.StatusUnauthorized},
	}...)
}

// TestClassicAllowList_ListenPathInEndpointPathUnchanged freezes the Classic
// behaviour TT-18034 must not touch: an endpoint path that includes the listen
// path still matches the full request URL, and the upstream receives the
// stripped path.
func TestClassicAllowList_ListenPathInEndpointPathUnchanged(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run("allow_unsafe_listen_path_matching="+jsonMarshalString(unsafe), func(t *testing.T) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.AllowUnsafeListenPathMatching = unsafe
			})
			defer ts.Close()

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/employees"
				spec.Proxy.StripListenPath = true
				spec.UseKeylessAccess = true
				UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
					v.UseExtendedPaths = true
					v.ExtendedPaths.WhiteList = []apidef.EndPointMeta{
						{Path: "/employees/static", Method: http.MethodGet},
						{Path: "/employees/{id}", Method: http.MethodGet},
					}
				})
			})

			_, _ = ts.Run(t, []test.TestCase{
				{Path: "/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/static"`},
				{Path: "/employees/hello_world", Code: http.StatusOK, BodyMatch: `"Url":"/hello_world"`},
				{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
				{Path: "/employees/foo/bar", Code: http.StatusOK, BodyMatch: `"Url":"/foo/bar"`},
			}...)
		})
	}
}
