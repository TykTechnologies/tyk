package oas

import "github.com/TykTechnologies/tyk/apidef"

// Internal holds the endpoint configuration, configuring the endpoint for internal requests.
// Tyk classic API definition: `version_data.versions...extended_paths.internal[*]`.
type Internal struct {
	// Enabled if set to true makes the endpoint available only for internal requests.
	Enabled bool `bson:"enabled" json:"enabled"`
}

// Fill fills *Internal receiver with data from apidef.InternalMeta.
func (i *Internal) Fill(meta apidef.InternalMeta) {
	i.Enabled = !meta.Disabled
}

// ExtractTo fills *apidef.InternalMeta from *Internal.
func (i *Internal) ExtractTo(meta *apidef.InternalMeta) {
	meta.Disabled = !i.Enabled
}

func fillInternal(meta apidef.InternalMeta, operation *Operation) {
	if operation.Internal == nil {
		operation.Internal = &Internal{}
	}

	operation.Internal.Fill(meta)
	if ShouldOmit(operation.Internal) {
		operation.Internal = nil
	}
}

func (o *Operation) extractInternalTo(ep *apidef.ExtendedPathsSet, path string, method string) {
	if o.Internal == nil {
		return
	}

	meta := apidef.InternalMeta{Path: path, Method: method}
	o.Internal.ExtractTo(&meta)
	ep.Internal = append(ep.Internal, meta)
}
