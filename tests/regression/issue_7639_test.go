package regression

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func Test_Issue7639(t *testing.T) {
	ts := gateway.StartTest(nil)
	defer ts.Close()

	// load api definition from file
	spec := loadAPISpec(t, "testdata/issue-7639-apidef.json")

	// produce form values
	form := url.Values{}
	form.Add("foo", "swiggetty")
	form.Add("bar", "swoggetty")
	form.Add("baz", "swoogetty")

	for _, enable := range []bool{true, false} {
		spec.EnableContextVars = enable
		ts.Gw.LoadAPI(spec)

		t.Run(fmt.Sprintf("Context vars enabled=%v", enable), func(t *testing.T) {

			// issue test request
			ts.Run(t, []test.TestCase{
				{
					Method: "GET",
					Path:   "/bug-report/",
					Code:   500,
				},
				{
					Method:  "POST",
					Path:    "/bug-report/",
					Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
					Data:    string(form.Encode()),
					Code:    500,
				},
			}...)
		})
	}
}
