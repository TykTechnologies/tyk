package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
)

const CacheTag = "Cache Invalidation"

func InvalidateCache(r *openapi3.Reflector) error {
	return invalidateCache(r)
}

func invalidateCache(r *openapi3.Reflector) error {
	// TODO::Ask why we don't have error 404 for this
	oc, err := r.NewOperationContext(http.MethodDelete, "/tyk/cache/{apiID}")
	if err != nil {
		return err
	}
	oc.SetTags(CacheTag)
	oc.SetSummary("Invalidate cache")
	oc.SetID("invalidateCache")
	oc.SetDescription("Invalidate cache for the given API")
	oc.AddRespStructure(apiStatusMessage{
		Status:  "ok",
		Message: "cache invalidated",
	})
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusInternalServerError))
	oc.AddRespStructure(new(apiStatusMessage), openapi.WithHTTPStatus(http.StatusForbidden))
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())

	return r.AddOperation(oc)
}
