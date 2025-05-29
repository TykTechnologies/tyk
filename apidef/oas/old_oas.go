package oas

import (
	"github.com/getkin/kin-openapi/openapi3"
)

// OldOAS serves for data model migration/conversion purposes (gorm).
type OldOAS struct {
	openapi3.T
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
