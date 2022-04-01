package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestSchemaApi(t *testing.T) {
	t.Parallel()
	g := StartTest(nil)
	defer g.Close()

	t.Run("return oas schema", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: "/tyk/schema?oasVersion=3.0.3",
			BodyMatch: `"status":"Success"`, Code: http.StatusOK})
	})

	t.Run("status not found when non existing version is queried", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: "/tyk/schema?oasVersion=2.0.3",
			BodyMatchFunc: func(bytes []byte) bool {
				var resp OASSchemaResponse
				err := json.Unmarshal(bytes, &resp)
				if err != nil {
					t.Logf("error while unmarshalling body in test: %v", err)
					return false
				}
				if resp.Message == `Schema not found for version "2.0.3"` && resp.Status == "Failed" {
					return true
				}
				return false
			}, Code: http.StatusNotFound})
	})

	t.Run("return latest version when oasVersion is not supplied", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: "/tyk/schema",
			BodyMatch: `"status":"Success"`, Code: http.StatusOK})
	})
}
