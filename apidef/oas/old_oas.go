package oas

import (
	openapifork "github.com/TykTechnologies/kin-openapi/openapi3"
	"github.com/TykTechnologies/tyk/apidef"

	"github.com/getkin/kin-openapi/openapi3"
)

type OldOAS struct {
	openapifork.T
}

// OldApiDefinition is used to query APIs with old OAS structure.
type OldApiDefinition struct {
	apidef.APIDefinition `bson:"api_definition,inline" json:"api_definition,inline"`
	OAS                  *OldOAS `bson:"oas,omitempty" json:"oas,omitempty"`
}

// ConvertToNewerOAS converts a deprecated OldOAS object to the newer OAS representation.
func (o *OldOAS) ConvertToNewerOAS() (*OAS, error) {
	outBytes, err := o.MarshalJSON()
	if err != nil {
		return nil, err
	}

	loader := openapi3.NewLoader()
	t, err := loader.LoadFromData(outBytes)
	if err != nil {
		return nil, err
	}

	return &OAS{T: *t}, nil
}
