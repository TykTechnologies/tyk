package gateway

import (
	"encoding/json"
	"fmt"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// Constant for event system.
const EH_CoProcessHandler apidef.TykEventHandlerName = "cp_dynamic_handler"

type CoProcessEventHandler struct {
	methodName string
	Spec       *APISpec
	SpecJSON   json.RawMessage
}

type CoProcessEventWrapper struct {
	Event    config.EventMessage `json:"message"`
	Handler  string              `json:"handler_name"`
	SpecJSON *json.RawMessage    `json:"spec"`
}

func (l *CoProcessEventHandler) Init(handlerConf interface{}) error {
	l.methodName = handlerConf.(map[string]interface{})["name"].(string)

	// Set the VM globals
	globalVals := JSVMContextGlobal{
		APIID: l.Spec.APIID,
		OrgID: l.Spec.OrgID,
	}

	gValAsJSON, err := json.Marshal(globalVals)
	if err != nil {
		return fmt.Errorf("failed to marshal globals: %v", err)
	}

	l.SpecJSON = json.RawMessage(gValAsJSON)
	return nil
}

func (l *CoProcessEventHandler) HandleEvent(em config.EventMessage) {
	dispatcher := loadedDrivers[l.Spec.CustomMiddleware.Driver]
	if dispatcher == nil {
		return
	}
	eventWrapper := CoProcessEventWrapper{
		Event:    em,
		Handler:  l.methodName,
		SpecJSON: &l.SpecJSON,
	}

	// JSON-encode the event data object
	msgAsJSON, err := json.Marshal(eventWrapper)
	if err != nil {
		log.Error("Failed to encode event data: ", err)
		return
	}
	dispatcher.DispatchEvent(msgAsJSON)
}
