package main

import (
	"github.com/lonelycode/tykcommon"
	"net/http"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformHeaders struct {
	TykMiddleware
}

type TransformHeadersConfig struct{}

// New lets you do any initialisations for the object can be done here
func (t *TransformHeaders) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *TransformHeaders) GetConfig() (interface{}, error) {
	return nil, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformHeaders) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	// Uee the request status validator to see if it's in our cache list
	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := t.TykMiddleware.Spec.GetVersionData(r)
	found, meta = t.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, HeaderInjected)
	if found {
		stat = StatusHeaderInjected
	}

	if stat == StatusHeaderInjected {
		thisMeta := meta.(tykcommon.HeaderInjectionMeta)

		for _, dKey := range thisMeta.DeleteHeaders {
			r.Header.Del(dKey)
		}

		for nKey, nVal := range thisMeta.AddHeaders {
			r.Header.Add(nKey, nVal)
		}

	}

	return nil, 200
}
