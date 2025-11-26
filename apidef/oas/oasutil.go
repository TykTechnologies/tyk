package oas

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
	internalreflect "github.com/TykTechnologies/tyk/internal/reflect"
)

// todo: check if it is usable
func toStructIfMap(input interface{}, val interface{}) bool {
	mapInput, ok := input.(map[string]interface{})
	if !ok {
		return false
	}

	inBytes, err := json.Marshal(mapInput)
	if err != nil {
		log.Debug("Map input couldn't be marshalled")
		return false
	}

	err = json.Unmarshal(inBytes, val)
	if err != nil {
		log.Debug("Unmarshalling to struct couldn't succeed")
		return false
	}

	return true
}

// ShouldOmit is a compatibility alias. It may be removed in the future.
var ShouldOmit = internalreflect.IsEmpty

func requireMainVersion(api *apidef.APIDefinition) apidef.VersionInfo {
	if len(api.VersionData.Versions) == 0 {
		api.VersionData.Versions = map[string]apidef.VersionInfo{
			Main: {},
		}
	}

	if _, ok := api.VersionData.Versions[Main]; !ok {
		api.VersionData.Versions[Main] = apidef.VersionInfo{}
	}

	return api.VersionData.Versions[Main]
}

func updateMainVersion(api *apidef.APIDefinition, updatedMainVersion apidef.VersionInfo) {
	api.VersionData.Versions[Main] = updatedMainVersion
}
