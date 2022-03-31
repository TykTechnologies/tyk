package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestSchemaApi(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	t.Run("return oas schema", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: "/tyk/schema?oasVersion=3.0.3",
			BodyMatch: `"status":"Success"`, Code: http.StatusOK})
	})

	t.Run("status not found when non existing version is queried", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: "/tyk/schema?oasVersion=2.0.3",
			BodyMatch: `"message":"Schema not found for version 2.0.3"`, Code: http.StatusNotFound})
	})

	t.Run("bad request when oasVersion is not supplied", func(t *testing.T) {
		_, _ = g.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodGet, Path: "/tyk/schema",
			BodyMatch: `"message":"Should provide a value for parameter oasVersion`, Code: http.StatusBadRequest})
	})
}
