package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/user"
)

func Keys(r *openapi3.Reflector) error {
	return getKeyWithID(r)
}

func getKeyWithID(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/keys/{keyID}")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(user.SessionState))
	oc.AddRespStructure(new(user.SessionState))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusNotFound))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusBadRequest))
	oc.SetTags("Keys")
	oc.SetID("getKey")
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{keyIDParameter()}
	par = append(par, getKeyQuery()...)
	o3.Operation().WithParameters(par...)
	oc.SetDescription("Get session info about the specified key. Should return up to date rate limit and quota usage numbers.")
	return r.AddOperation(oc)
}

func keyIDParameter() openapi3.ParameterOrRef {
	isRequired := true
	desc := "The Key ID"
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "keyID", Required: &isRequired, Description: &desc}.ToParameterOrRef()
}

func getKeyQuery() []openapi3.ParameterOrRef {
	hasDesc := "Use the hash of the key as input instead of the full key"
	isRequired := false
	///example:=false
	return []openapi3.ParameterOrRef{
		openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "hashed", Description: &hasDesc, Required: &isRequired}.ToParameterOrRef(),
	}
}
