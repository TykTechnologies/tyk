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
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/schema")
	if err != nil {
		return err
	}
	oc.SetID("getSchema")
	oc.SetTags("Schema")
	oc.SetSummary("Get OAS schema")
	oc.SetDescription("Get OAS schema")
	oc.AddRespStructure(new(gateway.OASSchemaResponse), openapi.WithHTTPStatus(http.StatusOK), func(cu *openapi.ContentUnit) {
		cu.Description = "OAS schema response"
	})
	oc.AddRespStructure(new(gateway.OASSchemaResponse), openapi.WithHTTPStatus(http.StatusNotFound), func(cu *openapi.ContentUnit) {
		cu.Description = "The response when the requested OAS schema is not found"
	})
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{oasVersionQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func oasVersionQuery(description ...string) openapi3.ParameterOrRef {
	desc := "The OAS version"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "oasVersion", Required: &isOptional, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}
