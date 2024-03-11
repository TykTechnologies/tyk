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

func createPolicy(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/policies")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.SetSummary("Create a Policy")
	oc.SetDescription("You can create a Policy in your Tyk Instance")
	oc.SetID("addPolicy")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddReqStructure(new(user.Policy))
	oc.AddRespStructure(new(apiModifyKeySuccess))
	return r.AddOperation(oc)
}

func getListOfPolicies(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/policies")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.AddRespStructure(new([]user.Policy))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetID("listPolicies")
	oc.SetSummary("List Policies")
	oc.SetDescription("You can retrieve all the policies in your Tyk instance. Returns an array policies.")
	return r.AddOperation(oc)
}

func getPolicyWithID(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/policies/{polID}")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.AddRespStructure(new(user.Policy))
	oc.SetSummary("Get a Policy")
	oc.SetDescription("You can retrieve details of a single policy by ID in your Tyk instance.")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetID("getPolicy")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{polIDParameter()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func deletePolicyWithID(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/policies/{polID}")
	if err != nil {
		return err
	}
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiModifyKeySuccess))
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
	oc, err := r.NewOperationContext(http.MethodPut, "/tyk/policies/{polID}")
	if err != nil {
		return err
	}
	oc.SetTags(PolicyTag)
	oc.SetID("updatePolicy")
	oc.SetSummary("Update a Policy")
	oc.SetDescription("You can update a Policy in your Tyk Instance by ID")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiModifyKeySuccess))
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
