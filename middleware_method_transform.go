package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformMethod struct {
	*TykMiddleware
}

func (t *TransformMethod) GetName() string {
	return "TransformMethod"
}

// New lets you do any initialisations for the object can be done here
func (t *TransformMethod) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (t *TransformMethod) GetConfig() (interface{}, error) {
	return nil, nil
}

func (t *TransformMethod) IsEnabledForSpec() bool {
	var used bool
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.MethodTransforms) > 0 {
			used = true
			break
		}
	}

	return used
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformMethod) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	_, versionPaths, _, _ := t.Spec.GetVersionData(r)
	found, meta := t.Spec.CheckSpecMatchesStatus(r.URL.Path, r.Method, versionPaths, MethodTransformed)
	if found {
		mmeta := meta.(*apidef.MethodTransformMeta)

		switch strings.ToUpper(mmeta.ToMethod) {
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
