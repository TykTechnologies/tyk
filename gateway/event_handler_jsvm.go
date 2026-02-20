package gateway

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
)

type JSVMContextGlobal struct {
	APIID string
	OrgID string
}

// JSVMEventHandler is a scriptable event handler
type JSVMEventHandler struct {
	conf     apidef.JSVMEventHandlerConf
	Spec     *APISpec
	SpecJSON string
	Gw       *Gateway `json:"-"`
}

// Init initializes the JSVMEventHandler by setting the method name and global values required for the JavaScript VM.
func (l *JSVMEventHandler) Init(handlerConf any) error {
	var err error
	if err = l.conf.Scan(handlerConf); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm_event_handler",
		}).Error("Problem getting configuration, skipping. ", err)
		return err
	}

	if l.conf.Disabled {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm_event_handler",
		}).Infof("skipping disabled jsvm event handler with method name %s at path %s", l.conf.MethodName, l.conf.Path)
		return ErrEventHandlerDisabled
	}

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
	_, err = l.Gw.GlobalEventsJSVM.Run(l.conf.MethodName + `.DoProcessEvent(` + string(msgAsJSON) + `,` + l.SpecJSON + `);`)
	if err != nil {
		log.WithError(err).Error("executing JSVM method")
	}
}
