package gateway

import (
	"net/http"
)

// PersistGraphQLOperationMiddleware lets you convert any HTTP request into a GraphQL Operation
type PersistGraphQLOperationMiddleware struct {
	BaseMiddleware
}

func (i *PersistGraphQLOperationMiddleware) Name() string {
	return "PersistGraphQLOperationMiddleware"
}

func (i *PersistGraphQLOperationMiddleware) EnabledForSpec() bool {
	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (i *PersistGraphQLOperationMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	vInfo, _ := i.Spec.Version(r)
	versionPaths := i.Spec.RxPaths[vInfo.Name]
	found, meta := i.Spec.CheckSpecMatchesStatus(r, versionPaths, PersistGraphQL)
	if !found {
		// PersistGraphQLOperationMiddleware not enabled for this endpoint
		return nil, http.StatusOK
	}
	_ = meta
	ctxSetRequestMethod(r, http.MethodPost)
	originalPath := r.URL
	ctxSetURLRewriteTarget(r, originalPath)
	r.Header.Set("Content-Type", "application/json")

	return nil, http.StatusOK
}
