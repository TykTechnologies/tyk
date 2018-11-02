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
	methodName string
	Spec       *APISpec
	SpecJSON   string
}

// New enables the intitialisation of event handler instances when they are created on ApiSpec creation
func (l *JSVMEventHandler) Init(handlerConf interface{}) error {
	l.methodName = handlerConf.(map[string]interface{})["name"].(string)

	// Set the VM globals
	globalVals := JSVMContextGlobal{
		APIID: l.Spec.APIID,
		OrgID: l.Spec.OrgID,
	}

	gValAsJSON, err := json.Marshal(globalVals)
	if err != nil {
		log.Error("Failed to marshal globals! ", err)
	}

	l.SpecJSON = string(gValAsJSON)
	return nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l *JSVMEventHandler) HandleEvent(em config.EventMessage) {
	// JSON-encode the event data object
	msgAsJSON, err := json.Marshal(em)
	if err != nil {
		log.Error("Failed to encode event data: ", err)
		return
	}

	// Execute the method name with the JSON object
	GlobalEventsJSVM.Run(l.methodName + `.DoProcessEvent(` + string(msgAsJSON) + `,` + l.SpecJSON + `);`)
}
