package gateway

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
	*BaseMiddleware
}

type modifiedMiddlewareConfig struct {
	CustomData string `mapstructure:"custom_data" json:"custom_data"`
}

func (m *modifiedMiddleware) Name() string {
	return "modifiedMiddleware"
}

// Init lets you do any initialisations for the object can be done here
func (m *modifiedMiddleware) Init() {}

// Config retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *modifiedMiddleware) Config() (interface{}, error) {
	var conf modifiedMiddlewareConfig

	err := mapstructure.Decode(m.Spec.ConfigData, &conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *modifiedMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	mconf := conf.(modifiedMiddlewareConfig)
	if mconf.CustomData == "error" {
		return errors.New("Forced error called"), 400
	}
	return nil, 200
}
