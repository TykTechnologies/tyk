package regression

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func Test_Issue10104(t *testing.T) {
	ts := gateway.StartTest(nil)
	t.Cleanup(ts.Close)

	// load api definition from file
	ts.Gw.LoadAPI(LoadAPISpec(t, "testdata/issue-10104-apidef.json"))

	// issue request against /test to trigger panic
	ts.Run(t, []test.TestCase{
		{Path: "/test/", Method: http.MethodGet, Code: http.StatusOK},
	}...)
}
