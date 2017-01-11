package main

import (
	"encoding/json"

	"github.com/TykTechnologies/tykcommon"
)

const (
	EH_JSVMHandler tykcommon.TykEventHandlerName = "eh_dynamic_handler"
)

type JSVMContextGlobal struct {
	APIID string
	OrgID string
}

// JSVMEventHandler is a scriptable event handler
type JSVMEventHandler struct {
	conf     map[string]interface{}
	Spec     *APISpec
	SpecJSON string
}

// New enables the intitialisation of event handler instances when they are created on ApiSpec creation
func (l JSVMEventHandler) New(handlerConf interface{}) (TykEventHandler, error) {
	thisHandler := JSVMEventHandler{}
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

	thisHandler.SpecJSON = string(gValAsJSON)

	return thisHandler, nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l JSVMEventHandler) HandleEvent(em EventMessage) {
	// 1. Get the methodName for the Event Handler
	methodName := l.conf["name"].(string)

	// 2. JSON-encode the event data object
	msgAsJSON, encErr := json.Marshal(em)
	if encErr != nil {
		log.Error("Failed to encode event data: ", encErr)
		return
	}

	// 3. Execute the method name with the JSON object
	GlobalEventsJSVM.VM.Run(methodName + `.DoProcessEvent(` + string(msgAsJSON) + `,` + l.SpecJSON + `);`)
}
