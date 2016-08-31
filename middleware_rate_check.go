package main

import (
	"net/http"
)

// ModifiedMiddleware is a sample custom middleware component, must inherit TykMiddleware
// so you have access to spec and definition data
type RateCheckMW struct {
	*TykMiddleware
}

type RateCheckMWConfig struct{}

// New lets you do any initialisations for the object can be done here
func (m *RateCheckMW) New() {}

func (m *RateCheckMW) IsEnabledForSpec() bool {
	return true
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *RateCheckMW) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *RateCheckMW) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Let's track r/ps
	GlobalRate.Incr(1)

	return nil, 200
}
