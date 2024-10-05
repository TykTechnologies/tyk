package gateway_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestValidateJSONSchema(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.TestPrepareValidateJSONSchema(true)

	_, _ = ts.Run(t, []test.TestCase{
		{Method: http.MethodPost, Path: "/without_validation", Data: "{not_valid}", Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/v", Data: `{"age":23}`, BodyMatch: `firstName: firstName is required; lastName: lastName is required`, Code: http.StatusUnprocessableEntity},
		{Method: http.MethodPost, Path: "/v", Data: `[]`, BodyMatch: `Expected: object, given: array`, Code: http.StatusUnprocessableEntity},
		{Method: http.MethodPost, Path: "/v", Data: `not_json`, Code: http.StatusBadRequest},
		{Method: http.MethodPost, Path: "/v", Data: `{"age":23, "firstName": "Harry", "lastName": "Potter"}`, Code: http.StatusOK},
		{Method: http.MethodPost, Path: "/v", Data: `{"age":23, "firstName": "Harry", "lastName": "Potter", "objs": "d"}`, Code: http.StatusUnprocessableEntity, BodyMatch: `objs: objs must be one of the following: \\"a\\", \\"b\\", \\"c\\"`},
	}...)

	t.Run("disabled", func(t *testing.T) {
		ts.TestPrepareValidateJSONSchema(false)

		_, _ = ts.Run(t, []test.TestCase{
			{Method: http.MethodPost, Path: "/without_validation", Data: "{not_valid}", Code: http.StatusOK},
			{Method: http.MethodPost, Path: "/v", Data: `{"age":23}`, Code: http.StatusOK}, // failed above
		}...)
	})

}

func BenchmarkValidateJSONSchema(b *testing.B) {
	b.ReportAllocs()

	ts := StartTest(nil)
	defer ts.Close()

	ts.TestPrepareValidateJSONSchema(true)

	for i := 0; i < b.N; i++ {
		ts.Run(b, []test.TestCase{
			{Method: "POST", Path: "/without_validation", Data: "{not_valid}", Code: http.StatusOK},
			{Method: "POST", Path: "/v", Data: `{"age":23}`, BodyMatch: `firstName: firstName is required; lastName: lastName is required`, Code: http.StatusUnprocessableEntity},
			{Method: "POST", Path: "/v", Data: `[]`, BodyMatch: `Expected: object, given: array`, Code: http.StatusUnprocessableEntity},
			{Method: "POST", Path: "/v", Data: `not_json`, Code: http.StatusBadRequest},
			{Method: "POST", Path: "/v", Data: `{"age":23, "firstName": "Harry", "lastName": "Potter"}`, Code: http.StatusOK},
		}...)
	}
}
