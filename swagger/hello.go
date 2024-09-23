package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/apidef"
)

const (
	helloTag     = "Health Checking"
	helloTagDesc = `Check health status of the Tyk Gateway and loaded APIs.
`
)

// Done
func HealthEndpoint(r *openapi3.Reflector) error {
	addTag(helloTag, helloTagDesc, optionalTagParameters{})
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/hello",
		OperationID: "hello",
		Tag:         helloTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Check the health of the Tyk Gateway.")
	oc.SetDescription("From v2.7.5 you can now rename the `/hello`  endpoint by using the `health_check_endpoint_name` option.")
	op.AddRespWithExample(healthCheckResponse, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Success."
	})
	op.AddGenericErrorResponse(http.StatusMethodNotAllowed, "Method Not Allowed")
	return op.AddOperation()
}

var healthCheckResponse = apidef.HealthCheckResponse{
	Status:      apidef.Pass,
	Version:     "v5.5.0-dev",
	Description: "Tyk GW",
	Details: map[string]apidef.HealthCheckItem{
		"redis": {
			Status:        apidef.Pass,
			ComponentType: "datastore",
			Time:          "2020-05-19T03:42:55+01:00",
		},
	},
}
