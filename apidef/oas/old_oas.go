package oas

import (
	"fmt"

	"github.com/pb33f/libopenapi"
)

// OldOAS serves for data model migration/conversion purposes (gorm).
// TODO: For OAS 3.1 support, this struct needs to be properly redesigned with libopenapi
type OldOAS struct {
	// Placeholder fields for migration - actual implementation needs proper libopenapi integration
	Data []byte // Store raw OAS data during migration
}

// ConvertToNewerOAS converts a deprecated OldOAS object to the newer OAS representation.
func (o *OldOAS) ConvertToNewerOAS() (*OAS, error) {
	// TODO: For OAS 3.1 support - implement proper conversion using libopenapi
	if len(o.Data) == 0 {
		return nil, fmt.Errorf("no OAS data available for conversion")
	}

	// Create libopenapi document from raw data
	document, err := libopenapi.NewDocument(o.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create libopenapi document: %w", err)
	}

	// Build the v3 model
	_, buildErrors := document.BuildV3Model()
	if len(buildErrors) > 0 {
		return nil, fmt.Errorf("failed to build v3 model: %v", buildErrors)
	}

	// TODO: For OAS 3.1 support - implement proper OAS creation from libopenapi document
	// For now, return an error since the OAS struct needs to be updated first
	return nil, fmt.Errorf("OAS creation from libopenapi document not yet implemented - requires OAS struct migration")
}

// MarshalJSON marshals the OldOAS data
func (o *OldOAS) MarshalJSON() ([]byte, error) {
	if len(o.Data) == 0 {
		return nil, fmt.Errorf("no data to marshal")
	}
	return o.Data, nil
}
