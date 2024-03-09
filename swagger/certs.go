package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/gateway"
)

const CertsTag = "Certs"

func Certs(r *openapi3.Reflector) error {
	err := deleteCertWithID(r)
	if err != nil {
		return err
	}
	return createCertificate(r)
}

func deleteCertWithID(r *openapi3.Reflector) error {
	// TODO::check if certID is in query
	// TODO::Check if  orgID is required
	// TODO:: why don't we have error 404
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/certs/{certID}")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	oc.SetTags(CertsTag)
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.SetID("deleteCerts")
	oc.SetSummary("Delete Certificate")
	oc.SetDescription("Delete certificate by id")
	oc.AddRespStructure(new(apiStatusMessage))
	par := []openapi3.ParameterOrRef{certIDParameter(), orgIDQuery("Organisation ID to list the certificates")}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func createCertificate(r *openapi3.Reflector) error {
	// TODO::Ask why we return 405 for bad body instead of 400
	// TODO:: to check if org is required
	// TODO:: what is the request body for this
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/certs")
	if err != nil {
		return err
	}
	oc.SetTags(CertsTag)
	oc.SetID("addCert")
	oc.SetSummary("Add a certificate")
	oc.SetDescription("Add a certificate to the Tyk Gateway")
	oc.AddRespStructure(new(gateway.APICertificateStatusMessage))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusMethodNotAllowed))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{orgIDQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func getCertsList(r *openapi3.Reflector) error {
	// TODO::This return different body depending on value of mode
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/keys")
	if err != nil {
		return err
	}
	oc.SetTags(CertsTag)
	oc.SetID("listCerts")
	oc.SetSummary("List Certificates")
	oc.SetDescription("List All Certificates in the Tyk Gateway")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{orgIDQuery(), certIDsQuery(), modeQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func orgIDQuery(description ...string) openapi3.ParameterOrRef {
	desc := "Organisation ID to list the certificates"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "org_id", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func modeQuery(description ...string) openapi3.ParameterOrRef {
	desc := "Mode to list the certificate details"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "mode", Required: &isOptional, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func certIDsQuery(description ...string) openapi3.ParameterOrRef {
	desc := "Comma separated list of certificates to list"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "certID", Required: &isOptional, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func certIDParameter() openapi3.ParameterOrRef {
	desc := "Certificate ID to be deleted"
	return openapi3.Parameter{In: openapi3.ParameterInPath, Name: "certID", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}
