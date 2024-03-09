package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/user"
)

const PolicyTag = "Policies"

func Policies(r *openapi3.Reflector) error {
	err := getListOfPolicies(r)
	if err != nil {
		return err
	}
	return createPolicy(r)
}

func createPolicy(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/policies")
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
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/policies")
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
