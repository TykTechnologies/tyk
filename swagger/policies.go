package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/user"
)

const PolicyTag = "Policies"

func PoliciesApis(r *openapi3.Reflector) error {
	return addOperations(r, getListOfPolicies, getPolicyWithID, updatePolicy, deletePolicyWithID, createPolicy)
}

// Done
func createPolicy(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/policies")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.SetSummary("Create a Policy")
	oc.SetDescription("You can create a Policy in your Tyk Instance")
	oc.SetID("addPolicy")
	statusInternalServerError(oc, "Internal server error.")
	statusBadRequest(oc, "Malformed request")
	forbidden(oc)
	oc.AddReqStructure(new(user.Policy), func(cu *openapi.ContentUnit) {
	})
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "Policy created"
	})
	return r.AddOperation(oc)
}

// Done
func getListOfPolicies(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/policies")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.AddRespStructure(new([]user.Policy), func(cu *openapi.ContentUnit) {
		cu.Description = "List of all policies"
	})
	forbidden(oc)
	oc.SetID("listPolicies")
	oc.SetSummary("List Policies")
	oc.SetDescription("You can retrieve all the policies in your Tyk instance. Returns an array policies.")
	return r.AddOperation(oc)
}

// Done
func getPolicyWithID(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/policies/{polID}")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.AddRespStructure(new(user.Policy), func(cu *openapi.ContentUnit) {
		cu.Description = "Get details of a single Policy"
	})
	oc.SetSummary("Get a Policy")
	oc.SetDescription("You can retrieve details of a single policy by ID in your Tyk instance.")
	forbidden(oc)
	statusNotFound(oc, "Policy not found")
	oc.SetID("getPolicy")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{polIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

// Done
func deletePolicyWithID(r *openapi3.Reflector) error {
	// TODO:: we return error 500 instead of 404 if policy is not available
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/policies/{polID}")
	if err != nil {
		return err
	}
	statusInternalServerError(oc, "Internal server error")
	statusBadRequest(oc, "Returned when you fail to specify an polID to delete")
	forbidden(oc)
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "Deleted policy by ID"
	})
	oc.SetID("deletePolicy")
	oc.SetSummary("Delete a Policy")
	oc.SetDescription("Delete a policy by ID in your Tyk instance.")
	oc.SetTags(PolicyTag)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{polIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func updatePolicy(r *openapi3.Reflector) error {
	//TODO:: Why don't we have error 404
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/policies/{polID}")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.SetID("updatePolicy")
	oc.SetSummary("Update a Policy")
	oc.SetDescription("You can update a Policy in your Tyk Instance by ID")
	statusInternalServerError(oc, "Internal server error")
	forbidden(oc)
	oc.AddRespStructure(new(apiModifyKeySuccess), func(cu *openapi.ContentUnit) {
		cu.Description = "Policy updated"
	})

	statusBadRequest(oc, "Returned when you fail to specify an polID to update or due to a malformed request body")
	oc.AddReqStructure(new(user.Policy))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{polIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func polIDParameter(description ...string) openapi3.ParameterOrRef {
	desc := "You can retrieve details of a single policy by ID in your Tyk instance."
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "polID", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}
