package oas

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/internal/reflect"
)

func toStructIfMap(input interface{}, val interface{}) bool {
	mapInput, ok := input.(map[string]interface{})
	if !ok {
		return false
	}

	inBytes, err := json.Marshal(mapInput)
	if err != nil {
		log.Debug("Map input couldn't be marshalled")
	}

	err = json.Unmarshal(inBytes, val)
	if err != nil {
		log.Debug("Unmarshalling to struct couldn't succeed")
	}

	return true
}

// ShouldOmit is a compatibility alias. It may be removed in the future.
var ShouldOmit = reflect.IsEmpty
