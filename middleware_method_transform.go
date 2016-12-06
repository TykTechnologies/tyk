package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tykcommon"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformMethod struct {
	*TykMiddleware
}

type TransformMethodConfig struct{}

// New lets you do any initialisations for the object can be done here
func (t *TransformMethod) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *TransformMethod) GetConfig() (interface{}, error) {
	return nil, nil
}

func (t *TransformMethod) IsEnabledForSpec() bool {
	var used bool
	for _, thisVersion := range t.TykMiddleware.Spec.VersionData.Versions {
		if len(thisVersion.ExtendedPaths.MethodTransforms) > 0 {
			used = true
			break
		}
	}

	return used
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformMethod) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	// Uee the request status validator to see if it's in our cache list
	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := t.TykMiddleware.Spec.GetVersionData(r)
	found, meta = t.TykMiddleware.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, MethodTransformed)
	if found {
		stat = StatusMethodTransformed
	}

	if stat == StatusMethodTransformed {
		thisMeta := meta.(*tykcommon.MethodTransformMeta)

		switch strings.ToUpper(thisMeta.ToMethod) {
		case "GET":
			r.Method = "GET"
			return nil, 200
		case "POST":
			r.Method = "POST"
			return nil, 200
		case "PUT":
			r.Method = "PUT"
			return nil, 200
		case "DELETE":
			r.Method = "DELETE"
			return nil, 200
		case "OPTIONS":
			r.Method = "OPTIONS"
			return nil, 200
		case "PATCH":
			r.Method = "PATCH"
			return nil, 200
		default:
			return errors.New("Method not allowed"), 405
		}

	}

	return nil, 200
}
