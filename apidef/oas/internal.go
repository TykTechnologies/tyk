package oas

import "github.com/TykTechnologies/tyk/apidef"

// Internal holds the endpoint configuration, configuring the endpoint for internal requests.
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
