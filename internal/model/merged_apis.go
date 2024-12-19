package model

import (
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
)

// MergedAPI combines the embeds the classic and adds the OAS API definition as a field.
type MergedAPI struct {
	*apidef.APIDefinition `json:"api_definition,inline"`
	OAS                   *oas.OAS `json:"oas"`
}

// Logger returns API detail fields for logging.
func (m *MergedAPI) LogFields() logrus.Fields {
	return logrus.Fields{
		"api_id": m.APIID,
		"org_id": m.OrgID,
		"name":   m.Name,
		"path":   m.Proxy.ListenPath,
	}
}

// MergedAPIList is the response body for FromDashboardService.
type MergedAPIList struct {
	Message []MergedAPI
	Nonce   string
}

func NewMergedAPIList(apis ...MergedAPI) *MergedAPIList {
	return &MergedAPIList{
		Message: apis,
	}
}

// Set sets the available classic API definitions to the MergedAPIList.
func (f *MergedAPIList) SetClassic(defs []*apidef.APIDefinition) {
	for _, def := range defs {
		f.Message = append(f.Message, MergedAPI{APIDefinition: def})
	}
}

// Filter, if enabled=true, will filter the internal api definitions by their tags.
func (f *MergedAPIList) Filter(enabled bool, tags ...string) []MergedAPI {
	if !enabled {
		return f.Message
	}

	if len(tags) == 0 {
		return nil
	}

	tagMap := map[string]bool{}
	for _, tag := range tags {
		tagMap[tag] = true
	}

	result := make([]MergedAPI, 0, len(f.Message))
	for _, v := range f.Message {
		if v.TagsDisabled {
			continue
		}
		for _, tag := range v.Tags {
			if ok := tagMap[tag]; ok {
				result = append(result, MergedAPI{v.APIDefinition, v.OAS})
				break
			}
		}
	}
	return result
}
