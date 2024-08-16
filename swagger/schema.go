package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
)

func SchemaAPi(r *openapi3.Reflector) error {
	return getSchemaRequest(r)
}

func getSchemaRequest(r *openapi3.Reflector) error {
	///TODO::we dont return error 400 from code as old api says (which is wrong)
	///TODO::we produce schema: {} for array is that accurate ?
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/schema",
		OperationID: "getSchema",
		Tag:         "Schema",
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Get OAS schema.")
	oc.SetDescription("Get OAS schema definition using a version.")
	op.AddRespWithExample(gateway.OASSchemaResponse{Status: "Success"}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "OAS schema response."
	})
	op.AddRespWithExample(gateway.OASSchemaResponse{
		Status:  "Failed",
		Message: "Schema not found for version \"4\"",
	}, http.StatusNotFound, func(cu *openapi.ContentUnit) {
		cu.Description = "Version not found"
	})

	op.AddQueryParameter("oasVersion", "The OAS version to fetch.", OptionalParameterValues{
		Example: valueToInterface("3.0.3"),
	})
	return op.AddOperation()
}
