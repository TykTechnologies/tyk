package quota

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

var (
	StartTest     = gateway.StartTest
	CreateSession = gateway.CreateSession
)

type APISpec = gateway.APISpec
type Test = gateway.Test

func setupQuotaLimit(tb testing.TB, ts *Test, name string, data map[string]interface{}) {
	tb.Helper()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.UseKeylessAccess = true
		spec.Proxy.ListenPath = "/"
	})

	ts.Run(tb, test.TestCase{
		Path:      "/tyk/org/keys/" + name + "?reset_quota=1",
		AdminAuth: true,
		Method:    http.MethodPost,
		Code:      http.StatusOK,
		Data:      data,
	})
}
