package main

import (
	"errors"
	"net/http"

	"github.com/mitchellh/mapstructure"
)

// It's very easy to create custom middleware
// TODO: Write the docs around this

// ModifiedMiddleware is a sample custom middleware component, must inherit TykMiddleware
// so you have access to spec and definition data
type ModifiedMiddleware struct {
	*TykMiddleware
}

type ModifiedMiddlewareConfig struct {
	CustomConfigVar string `mapstructure:"custom_config_var" bson:"custom_config_var" json:"custom_config_var"`
}

func (mw *ModifiedMiddleware) GetName() string {
	return "ModifiedMiddleware"
}

// New lets you do any initialisations for the object can be done here
func (m *ModifiedMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *ModifiedMiddleware) GetConfig() (interface{}, error) {
	var thisModuleConfig ModifiedMiddlewareConfig

	err := mapstructure.Decode(m.TykMiddleware.Spec.APIDefinition.RawData, &thisModuleConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return thisModuleConfig, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *ModifiedMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	var thisConfig ModifiedMiddlewareConfig
	thisConfig = configuration.(ModifiedMiddlewareConfig)
	log.Info("Custom configuration: ", thisConfig.CustomConfigVar)

	if thisConfig.CustomConfigVar == "error" {
		return errors.New("Forced error called"), 400
	}

	return nil, 200
}
