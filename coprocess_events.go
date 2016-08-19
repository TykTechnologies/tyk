// +build coprocess

package main

import (
	"github.com/TykTechnologies/tykcommon"
	// "fmt"
	"encoding/json"
)

// Constant for event system.
const (
	EH_CoProcessHandler tykcommon.TykEventHandlerName = "cp_dynamic_handler"
)

type CoProcessEventHandler struct {
	conf     map[string]interface{}
	Spec     *APISpec
	SpecJSON json.RawMessage
}

type CoProcessEventWrapper struct {
	Event    EventMessage     `json:"message"`
	Handler  string           `json:"handler_name"`
	SpecJSON *json.RawMessage `json:"spec"`
}

func (l CoProcessEventHandler) New(handlerConf interface{}) (TykEventHandler, error) {
	thisHandler := CoProcessEventHandler{}
	thisHandler.Spec = l.Spec
	thisHandler.conf = handlerConf.(map[string]interface{})

	// Set the VM globals
	globalVals := JSVMContextGlobal{
		APIID: l.Spec.APIID,
		OrgID: l.Spec.OrgID,
	}

	gValAsJSON, gErr := json.Marshal(globalVals)
	if gErr != nil {
		log.Error("Failed to marshal globals! ", gErr)
	}

	// thisHandler.SpecJSON = string(gValAsJSON)
	thisHandler.SpecJSON = json.RawMessage(gValAsJSON)

	return thisHandler, nil
}

func (l CoProcessEventHandler) HandleEvent(em EventMessage) {
	// 1. Get the methodName for the Event Handler
	methodName := l.conf["name"].(string)

	eventWrapper := CoProcessEventWrapper{
		Event:    em,
		Handler:  methodName,
		SpecJSON: &l.SpecJSON,
	}

	// 2. JSON-encode the event data object
	msgAsJSON, encErr := json.Marshal(eventWrapper)
	if encErr != nil {
		log.Error("Failed to encode event data: ", encErr)
		return
	}

	GlobalDispatcher.DispatchEvent(msgAsJSON)
}
