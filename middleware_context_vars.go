package main

import (
	"github.com/gorilla/context"
	"net/http"
	"strings"
)

type MiddlewareContextVars struct {
	*TykMiddleware
}

type MiddlewareContextVarsConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *MiddlewareContextVars) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *MiddlewareContextVars) GetConfig() (interface{}, error) {
	var thisModuleConfig MiddlewareContextVarsConfig
	return thisModuleConfig, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *MiddlewareContextVars) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	if !config.EnableContextVars {
		return nil, 200
	}

	copiedRequest := CopyHttpRequest(r)
	contextDataObject := make(map[string]interface{})

	if copiedRequest != nil {
		copiedRequest.ParseForm()

		// Form params (map[string][]string)
		contextDataObject["request_data"] = copiedRequest.Form

		// Path parts
		segmentedPathArray := strings.Split(copiedRequest.URL.Path, "/")
		contextDataObject["path_parts"] = segmentedPathArray

		// Key data
		authHeaderValue := context.Get(r, AuthHeaderValue)
		contextDataObject["token"] = authHeaderValue

		// path data
		contextDataObject["path"] = copiedRequest.URL.Path
	}

	log.Debug("Context Data Object: ", contextDataObject)

	context.Set(r, ContextData, contextDataObject)

	return nil, 200
}
