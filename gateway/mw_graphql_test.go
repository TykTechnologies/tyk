package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

func TestGraphQL(t *testing.T) {
	defer ResetTestConfig()
	ts := StartTest()
	defer ts.Close()

	BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"

		v1 := apidef.VersionInfo{Name: "v1"}
		v1.GraphQL.Schema = "foobar"
		spec.VersionData.Versions["v1"] = v1
	})

	ts.Run(t, []test.TestCase{
		{Path: "/get", Code: 200},
	}...)
}
