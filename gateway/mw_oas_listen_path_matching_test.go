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

// buildEmployeesOASAPI builds an OAS API whose listen path is a text prefix of
// its own endpoint paths, as reported in TT-18034.
func buildEmployeesOASAPI() *APISpec {
	paths := openapi3.NewPaths()
	paths.Set("/employees/static", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatic",
			Responses:   oasResponse200(),
		},
	})
	paths.Set("/employees/{id}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getById",
			Parameters: openapi3.Parameters{
				pathParam("id", &openapi3.Schema{Type: &openapi3.Types{"integer"}}),
			},
			Responses: oasResponse200(),
		},
	})

	spec := BuildOASAPI(func(oasDef *oas.OAS) {
		oasDef.Paths = paths
		ext := oasDef.GetTykExtension()
		ext.Info.State.Active = true
		ext.Server.ListenPath = oas.ListenPath{Value: "/employees", Strip: true}
		ext.Middleware = &oas.Middleware{
			Operations: oas.Operations{
				"getStatic": {
					Allow:           &oas.Allowance{Enabled: true},
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: http.StatusUnprocessableEntity},
				},
				"getById": {
					Allow:           &oas.Allowance{Enabled: true},
					ValidateRequest: &oas.ValidateRequest{Enabled: true, ErrorResponseCode: http.StatusUnprocessableEntity},
				},
			},
		}
	})[0]
	spec.UseKeylessAccess = true

	return spec
}

func TestOASAllowList_ListenPathPrefixOfEndpoints(t *testing.T) {
	t.Run("endpoints match only the path proxied upstream", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.LoadAPI(buildEmployeesOASAPI())

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/employees/123", Code: http.StatusOK, BodyMatch: `"Url":"/employees/123"`},
			{Path: "/employees/employees/abc", Code: http.StatusUnprocessableEntity},
			{Path: "/employees/static", Code: http.StatusForbidden},
			{Path: "/employees/hello_world", Code: http.StatusForbidden},
			{Path: "/employees/foo/bar", Code: http.StatusForbidden},
		}...)
	})

	t.Run("apply_legacy_oas_path_matching restores the full URL fallback", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.ApplyLegacyOASPathMatching = true
		})
		defer ts.Close()

		ts.Gw.LoadAPI(buildEmployeesOASAPI())

		_, _ = ts.Run(t, []test.TestCase{
			{Path: "/employees/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/employees/static"`},
			{Path: "/employees/employees/abc", Code: http.StatusUnprocessableEntity},
			{Path: "/employees/static", Code: http.StatusOK, BodyMatch: `"Url":"/static"`},
			{Path: "/employees/hello_world", Code: http.StatusOK, BodyMatch: `"Url":"/hello_world"`},
			{Path: "/employees/foo/bar", Code: http.StatusOK, BodyMatch: `"Url":"/foo/bar"`},
		}...)
	})
}

// TestClassicAllowList_ListenPathInEndpointPathUnchanged freezes the Classic
// behaviour TT-18034 must not touch: an endpoint path that includes the listen
// path still matches the full request URL, and the upstream receives the
// stripped path.
func TestClassicAllowList_ListenPathInEndpointPathUnchanged(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run("apply_legacy_oas_path_matching="+jsonMarshalString(legacy), func(t *testing.T) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.ApplyLegacyOASPathMatching = legacy
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
