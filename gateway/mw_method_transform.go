package gateway

import (
	"errors"
	"net/http"
	"strings"

	"github.com/TykTechnologies/tyk/v3/apidef"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type TransformMethod struct {
	BaseMiddleware
}

func (t *TransformMethod) Name() string {
	return "TransformMethod"
}

func (t *TransformMethod) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.MethodTransforms) > 0 {
			return true
		}
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *TransformMethod) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	_, versionPaths, _, _ := t.Spec.Version(r)
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, MethodTransformed)
	if !found {
		return nil, http.StatusOK
	}
	mmeta := meta.(*apidef.MethodTransformMeta)
	toMethod := strings.ToUpper(mmeta.ToMethod)

	ctxSetRequestMethod(r, r.Method)

	switch strings.ToUpper(mmeta.ToMethod) {
	case "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH":
		ctxSetTransformRequestMethod(r, toMethod)
	default:
		return errors.New("Method not allowed"), http.StatusMethodNotAllowed
	}
	return nil, http.StatusOK
}
