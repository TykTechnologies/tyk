package oas

import (
	"github.com/TykTechnologies/tyk/apidef"
)

type TrafficShaping struct {
	Enabled             bool               `bson:"enabled" json:"enabled"`
	Percentage          int                `bson:"percentage" json:"percentage"`
	ConsistentRouting   *ConsistentRouting `bson:"consistentRouting,omitempty" json:"consistentRouting,omitempty"`
	AlternativeEndpoint string             `bson:"alternativeEndpoint,omitempty" json:"alternativeEndpoint,omitempty"`
}

type ConsistentRouting struct {
	HeaderName string `bson:"headerName" json:"headerName"`
	QueryName  string `bson:"queryName,omitempty" json:"queryName,omitempty"`
}

func (t *TrafficShaping) Fill(api apidef.APIDefinition) {
	t.Enabled = false
	t.Percentage = 100
}

func (t *TrafficShaping) ExtractTo(api *apidef.APIDefinition) {
}

func (t *TrafficShaping) Validate() error {
	if !t.Enabled {
		return nil
	}

	if t.Percentage < 0 || t.Percentage > 100 {
		return ErrInvalidPercentage
	}

	return nil
}
