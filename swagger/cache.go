package swagger

import (
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
)

const (
	CacheTag     = "Cache Invalidation"
	CacheTagDesc = `Sometimes a cache might contain stale data, or it may just need to be cleared because of an invalid configuration. This call will purge all keys associated with a cache on an API-by-API basis.
`
)

func InvalidateCache(r *openapi3.Reflector) error {
	addTag(CacheTag, CacheTagDesc)
	return invalidateCache(r)
}

// Done
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
	}, func(cu *openapi.ContentUnit) {
		cu.Description = "cache invalidated"
	})
	statusInternalServerError(oc, "when cache invalidation fails")
	forbidden(oc)
	o3, ok := oc.(openapi3.OperationExposer)
	if !ok {
		return ErrOperationExposer
	}
	o3.Operation().WithParameters(apIIDParameter())

	return r.AddOperation(oc)
}
