package swagger

import (
	"crypto/x509/pkix"
	"net/http"
	"time"

	"github.com/swaggest/jsonschema-go"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/gateway"
)

const (
	CertsTag        = "Certs"
	certDescription = "Use the endpoints under this tag to manage your certificates. You can add, delete and list certificates using these endpoints."
)

func Certs(r *openapi3.Reflector) error {
	addTag(CertsTag, certDescription, optionalTagParameters{})
	return addOperations(r, deleteCertWithID, createCertificate, getCertsList, getCertsWithIDs)
}

// Done
func deleteCertWithID(r *openapi3.Reflector) error {
	// TODO:: why don't we have error 404
	// TODO::in previous OAS this was wrong
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/certs/{certID}",
		OperationID: "deleteCerts",
		Tag:         CertsTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetID("deleteCerts")
	oc.SetSummary("Delete Certificate")
	oc.SetDescription("Delete certificate by id")
	op.AddGenericStatusOk("removed", func(cu *openapi.ContentUnit) {
		cu.Description = "Deleted certificate"
	})
	op.AddPathParameter("certID", "Certificate ID to be deleted", OptionalParameterValues{
		Example: valueToInterface("5e9d9544a1dcd60001d0ed20a6ab77653d5da938f452bb8cc9b55b0630a6743dabd8dc92bfb025abb09ce035"),
	})
	op.AddQueryParameter("org_id", "Organisation ID to delete the certificates from", OptionalParameterValues{
		Example: valueToInterface("5e9d9544a1dcd60001d0ed20"),
	})
	return op.AddOperation()
}

// Done
func getCertsWithIDs(r *openapi3.Reflector) error {
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodGet,
		PathPattern: "/tyk/certs/{certID}",
		OperationID: "listCertsWithIDs",
		Tag:         "CertsTag",
	})
	if err != nil {
		return err
	}
	oc := op.oc
	op.StatusNotFound("Certificate with given SHA256 fingerprint not found")
	op.AddRespWithRefExamples(http.StatusOK, jsonschema.OneOf(new(certs.CertificateMeta), new([]*certs.CertificateMeta)), []multipleExamplesValues{
		{
			key:         certificateMetaListExample,
			httpStatus:  http.StatusOK,
			Summary:     "When multiple cert ID are sent",
			exampleType: Component,
			ref:         certificateMetaListExample,
			hasExample:  true,
		},
		{
			key:         certificateMetaExample,
			httpStatus:  http.StatusOK,
			Summary:     "When a single cert ID is sent",
			exampleType: Component,
			ref:         certificateMetaExample,
			hasExample:  true,
		},
	})
	op.AddPathParameter("certID", "Comma separated list of certificates to list", OptionalParameterValues{
		Example: valueToInterface("e6ce2b49-3e31-44de-95a7-12f054724283,5e9d9544a1dcd60001d0ed20a6ab77653d5da938f452bb8cc9b55b0630a6743dabd8dc92bfb025abb09ce035"),
	})
	oc.SetSummary("Return one certificate or List multiple Certificates in the Tyk Gateway given a comma separated list of certIDs")
	oc.SetDescription("Note that the certID path parameter can take a list of certIDs separated with commas (e.g /tyk/certs/certIDOne,certIDTwo).\n If you send a single certID it will return a single CertificateMeta object otherwise if you send more than two certIDs is will return an array of CertificateMeta objects.")
	return op.AddOperation()
}

// Done
func createCertificate(r *openapi3.Reflector) error {
	// TODO::Ask why we return 405 for bad body instead of 400
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodPost,
		PathPattern: "/tyk/certs",
		OperationID: "addCert",
		Tag:         CertsTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.AddReqStructure(new(string), openapi.WithContentType("text/plain"), func(cu *openapi.ContentUnit) {
	})
	oc.SetSummary("Add a certificate")
	oc.SetDescription("Add a certificate to the Tyk Gateway")
	op.AddGenericErrorResponse(http.StatusForbidden, "Certificate with  id already exists", func(cu *openapi.ContentUnit) {
		cu.Description = "When certificates you send already exist in the gateway"
	})
	op.AddGenericErrorResponse(http.StatusMethodNotAllowed, "Malformed request body", func(cu *openapi.ContentUnit) {
		cu.Description = "malformed request body"
	})
	op.AddRespWithExample(gateway.APICertificateStatusMessage{
		CertID:  "5e9d9544a1dcd60001d0ed207c440d66ebb0a4629d21329808dce9091acf5f2fde328067a6e60e5347271d90",
		Status:  "ok",
		Message: "Certificate added",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "New Certificate added"
	})
	op.AddQueryParameter("org_id", "Organisation ID to add the certificate to", OptionalParameterValues{
		Example: valueToInterface("5e9d9544a1dcd60001d0ed20"),
	})
	return op.AddOperation()
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
	var example interface{} = "detailed"
	desc := "Mode to list the certificate details"
	if len(description) != 0 {
		desc = description[0]
	}
	return openapi3.Parameter{In: openapi3.ParameterInQuery, Name: "mode", Required: &isOptional, Description: &desc, Schema: &openapi3.SchemaOrRef{
		Schema: &openapi3.Schema{
			Type:    &stringType,
			Example: &example,
			Enum:    []interface{}{"detailed"},
		},
	}}.ToParameterOrRef()
}

var certificates = []certs.CertificateMeta{
	{
		ID:            "5e9d9544a1dcd60001d0ed207c440d66ebb0a4629d21329808dce9091acf5f2fde328067a6e60e5347271d90",
		Fingerprint:   "7c440d66ebb0a4629d21329808dce9091acf5f2fde328067a6e60e5347271d90",
		HasPrivateKey: false,
		Issuer: pkix.Name{
			Country:            []string{"Peachtree"},
			Organization:       []string{"tyk"},
			OrganizationalUnit: []string{"tyk"},
			CommonName:         "tyk.io",
			Names: []pkix.AttributeTypeAndValue{
				{Type: []int{2, 5, 4, 6}, Value: "Peachtree"},
				{Type: []int{2, 5, 4, 10}, Value: "tyk"},
				{Type: []int{2, 5, 4, 11}, Value: "tyk"},
				{Type: []int{2, 5, 4, 3}, Value: "tyk.io"},
				{Type: []int{1, 2, 840, 113549, 1, 9, 1}, Value: "support@tyk.io"},
			},
		},
		Subject: pkix.Name{
			Country:            []string{"Peachtree"},
			Organization:       []string{"tyk"},
			OrganizationalUnit: []string{"tyk"},
			CommonName:         "tyk.io",
			Names: []pkix.AttributeTypeAndValue{
				{Type: []int{2, 5, 4, 6}, Value: "Peachtree"},
				{Type: []int{2, 5, 4, 10}, Value: "tyk"},
				{Type: []int{2, 5, 4, 11}, Value: "tyk"},
				{Type: []int{2, 5, 4, 3}, Value: "tyk.io"},
				{Type: []int{1, 2, 840, 113549, 1, 9, 1}, Value: "support@tyk.io"},
			},
		},
		NotBefore: time.Date(2024, 3, 25, 8, 46, 37, 0, time.UTC),
		NotAfter:  time.Date(2034, 3, 26, 8, 46, 37, 0, time.UTC),
		DNSNames:  []string{".*tyk.io"},
		IsCA:      false,
	},
}
