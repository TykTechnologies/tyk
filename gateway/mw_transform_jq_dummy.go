//go:build !jq
// +build !jq

package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
)

type TransformJQMiddleware struct {
	BaseMiddleware
}

func (t *TransformJQMiddleware) Name() string {
	return "TransformJQMiddleware"
}

func (t *TransformJQMiddleware) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.TransformJQ) > 0 {
			log.Warning("JQ transform not supported.")
			return false
		}
	}

	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformJQMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	return nil, 200
}

type TransformJQSpec struct {
	apidef.TransformJQMeta
}

func (a *APIDefinitionLoader) compileTransformJQPathSpec(paths []apidef.TransformJQMeta, stat URLStatus) []URLSpec {
	return []URLSpec{}
}
