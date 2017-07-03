package main

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

const EH_JSVMHandler apidef.TykEventHandlerName = "eh_dynamic_handler"

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
func (l *JSVMEventHandler) New(handlerConf interface{}) (config.TykEventHandler, error) {
	handler := &JSVMEventHandler{}
	handler.Spec = l.Spec
	handler.conf = handlerConf.(map[string]interface{})

	// Set the VM globals
	globalVals := JSVMContextGlobal{
		APIID: l.Spec.APIID,
		OrgID: l.Spec.OrgID,
	}

	gValAsJSON, err := json.Marshal(globalVals)
	if err != nil {
		log.Error("Failed to marshal globals! ", err)
	}

	handler.SpecJSON = string(gValAsJSON)

	return handler, nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l *JSVMEventHandler) HandleEvent(em config.EventMessage) {
	// 1. Get the methodName for the Event Handler
	methodName := l.conf["name"].(string)

	// 2. JSON-encode the event data object
	msgAsJSON, err := json.Marshal(em)
	if err != nil {
		log.Error("Failed to encode event data: ", err)
		return
	}

	// 3. Execute the method name with the JSON object
	GlobalEventsJSVM.VM.Run(methodName + `.DoProcessEvent(` + string(msgAsJSON) + `,` + l.SpecJSON + `);`)
}
