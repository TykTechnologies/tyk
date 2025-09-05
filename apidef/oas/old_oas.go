package oas

import (
	"fmt"
)

// OldOAS serves for data model migration/conversion purposes (gorm).
// TODO: For OAS 3.1 support, this struct needs to be properly redesigned with libopenapi
type OldOAS struct {
	// Placeholder fields for migration - actual implementation needs proper libopenapi integration
	Data []byte // Store raw OAS data during migration
}

// ConvertToNewerOAS converts a deprecated OldOAS object to the newer OAS representation.
func (o *OldOAS) ConvertToNewerOAS() (*OAS, error) {
	if len(o.Data) == 0 {
		return nil, fmt.Errorf("no OAS data available for conversion")
	}

	// Create new OAS and load data using the new LoadFromData method
	oas := &OAS{}
	err := oas.LoadFromData(o.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to load OAS data: %w", err)
	}

	return oas, nil
}

// MarshalJSON marshals the OldOAS data
func (o *OldOAS) MarshalJSON() ([]byte, error) {
	if len(o.Data) == 0 {
		return nil, fmt.Errorf("no data to marshal")
	}
	return o.Data, nil
}
