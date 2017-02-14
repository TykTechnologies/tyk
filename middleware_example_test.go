package main

import (
	"errors"
	"net/http"

	"github.com/mitchellh/mapstructure"
)

// It's very easy to create custom middleware
// TODO: Write the docs around this

// modifiedMiddleware is a sample custom middleware component, must inherit TykMiddleware
// so you have access to spec and definition data
type modifiedMiddleware struct {
	*TykMiddleware
}

type modifiedMiddlewareConfig struct {
	CustomConfigVar string `mapstructure:"custom_config_var" bson:"custom_config_var" json:"custom_config_var"`
}

func (m *modifiedMiddleware) GetName() string {
	return "modifiedMiddleware"
}

// New lets you do any initialisations for the object can be done here
func (m *modifiedMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *modifiedMiddleware) GetConfig() (interface{}, error) {
	var moduleConfig modifiedMiddlewareConfig

	err := mapstructure.Decode(m.TykMiddleware.Spec.APIDefinition.RawData, &moduleConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return moduleConfig, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *modifiedMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	conf := configuration.(modifiedMiddlewareConfig)
	log.Info("Custom configuration: ", conf.CustomConfigVar)

	if conf.CustomConfigVar == "error" {
		return errors.New("Forced error called"), 400
	}

	return nil, 200
}
