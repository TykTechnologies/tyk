package swagger

import (
	"net/http"

	"github.com/swaggest/jsonschema-go"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/gateway"
)

const CertsTag = "Certs"

func Certs(r *openapi3.Reflector) error {
	return addOperations(r, deleteCertWithID, createCertificate, getCertsList, getCertsWithIDs)
}

// Done
func deleteCertWithID(r *openapi3.Reflector) error {
	// TODO:: why don't we have error 404
	// TODO::in previous OAS this was wrong
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/certs/{certID}")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	oc.SetTags(CertsTag)
	forbidden(oc)
	oc.SetID("deleteCerts")
	oc.SetSummary("Delete Certificate")
	oc.SetDescription("Delete certificate by id")
	oc.AddRespStructure(new(apiStatusMessage), func(cu *openapi.ContentUnit) {
		cu.Description = "Deleted certificate"
	})
	par := []openapi3.ParameterOrRef{certIDParameter(), optionalOrgIDQuery("Organisation ID to delete the certificates from")}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

// Done
func getCertsWithIDs(r *openapi3.Reflector) error {
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/certs/{certID}")
	if err != nil {
		return err
	}
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	forbidden(oc)
	statusNotFound(oc, "When you send a single certID and it does not exist")
	oc.AddRespStructure(jsonschema.OneOf(new(certs.CertificateMeta), new([]*certs.CertificateMeta)), func(cu *openapi.ContentUnit) {
		cu.Description = "Certificates returned successfully"
	})
	par := []openapi3.ParameterOrRef{multipleCertIDsParameter()}
	o3.Operation().WithParameters(par...)
	oc.SetTags(CertsTag)
	oc.SetID("listCertsWithIDs")
	oc.SetSummary("Return one certificate or List multiple Certificates in the Tyk Gateway given a comma separated list of certIDs")
	oc.SetDescription("Note that the certID path parameter can take a list of certIDs separated with commas (e.g /tyk/certs/certIDOne,certIDTwo).\n If you send a single certID it will return a single CertificateMeta object otherwise if you send more than two certIDs is will return an array of CertificateMeta objects.")
	return r.AddOperation(oc)
}

// Done
func createCertificate(r *openapi3.Reflector) error {
	// TODO::Ask why we return 405 for bad body instead of 400
	oc, err := r.NewOperationContext(http.MethodPost, "/tyk/certs")
	if err != nil {
		return err
	}
	oc.AddReqStructure(new(string), openapi.WithContentType("text/plain"), func(cu *openapi.ContentUnit) {
	})
	oc.SetTags(CertsTag)
	oc.SetID("addCert")
	oc.SetSummary("Add a certificate")
	oc.SetDescription("Add a certificate to the Tyk Gateway")
	oc.AddRespStructure(new(gateway.APICertificateStatusMessage), func(cu *openapi.ContentUnit) {
		cu.Description = "New Certificate added"
	})
	forbidden(oc, "When certificates you send already exist in the gateway")
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusMethodNotAllowed), func(cu *openapi.ContentUnit) {
		cu.Description = "When you send a malformed request body"
	})
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{orgIDQuery("Organisation ID to add the certificate to")}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

// Done
func getCertsList(r *openapi3.Reflector) error {
	// TODO::In previous swagger we had a certID query parameter which was wrong.
	oc, err := r.NewOperationContext(http.MethodGet, "/tyk/certs")
	if err != nil {
		return err
	}
	oc.AddRespStructure(jsonschema.OneOf(new(gateway.APIAllCertificateBasics), new(gateway.APIAllCertificates)))
	oc.SetTags(CertsTag)
	oc.SetID("listCerts")
	oc.SetSummary("List Certificates")
	oc.SetDescription("List All Certificates in the Tyk Gateway")
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	par := []openapi3.ParameterOrRef{orgIDQuery(), certModeQuery()}
	o3.Operation().WithParameters(par...)
	return r.AddOperation(oc)
}

func optionalOrgIDQuery(description ...string) openapi3.ParameterOrRef {
	var example interface{} = "5e9d9544a1dcd60001d0ed20"
	desc := "Organisation ID to delete the certificates from"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "org_id", Example: &example, Required: &isOptional, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func orgIDQuery(description ...string) openapi3.ParameterOrRef {
	var example interface{} = "5e9d9544a1dcd60001d0ed20"
	desc := "Organisation ID to list the certificates"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Example: &example, Name: "org_id", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func certModeQuery(description ...string) openapi3.ParameterOrRef {
	stringType := openapi3.SchemaTypeString

	desc := "Mode to list the certificate details"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "mode", Required: &isOptional, Description: &desc, Schema: &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type: &stringType,
			Enum: []interface{}{"detailed"},
		},
	}}.ToParameterOrRef()
}

func modeQuery(description ...string) openapi3.ParameterOrRef {
	desc := "Mode to list the certificate details"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "mode", Required: &isOptional, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func multipleCertIDsParameter(description ...string) openapi3.ParameterOrRef {
	desc := "Comma separated list of certificates to list"
	if len(description) != 0 {
		desc = description[0]
	}
	var example interface{} = "e6ce2b49-3e31-44de-95a7-12f054724283,5e9d9544a1dcd60001d0ed20a6ab77653d5da938f452bb8cc9b55b0630a6743dabd8dc92bfb025abb09ce035"
	return openapi3.Parameter{In: openapi3.ParameterInPath, Example: &example, Name: "certID", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}

func certIDParameter() openapi3.ParameterOrRef {
	var example interface{} = "5e9d9544a1dcd60001d0ed20a6ab77653d5da938f452bb8cc9b55b0630a6743dabd8dc92bfb025abb09ce035"
	desc := "Certificate ID to be deleted"
	return openapi3.Parameter{In: openapi3.ParameterInPath, Example: &example, Name: "certID", Required: &isRequired, Description: &desc, Schema: stringSchema()}.ToParameterOrRef()
}
