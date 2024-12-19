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
	addTag(CacheTag, CacheTagDesc, optionalTagParameters{})
	return invalidateCache(r)
}

// Done
func invalidateCache(r *openapi3.Reflector) error {
	// TODO::Ask why we don't have error 404 for this
	op, err := NewOperationWithSafeExample(r, SafeOperation{
		Method:      http.MethodDelete,
		PathPattern: "/tyk/cache/{apiID}",
		OperationID: "invalidateCache",
		Tag:         CacheTag,
	})
	if err != nil {
		return err
	}
	oc := op.oc
	oc.SetSummary("Invalidate cache.")

	oc.SetDescription("Invalidate cache for the given API.")
	op.AddPathParameter("apiID", "The API ID.", OptionalParameterValues{
		Example: valueToInterface("ae67bb862a3241a49117508e0f9ee839"),
	})
	op.AddRespWithExample(apiStatusMessage{
		Status:  "ok",
		Message: "cache invalidated",
	}, http.StatusOK, func(cu *openapi.ContentUnit) {
		cu.Description = "Cache invalidated."
	})
	op.StatusInternalServerError("Cache invalidation failed.")
	return op.AddOperation()
}
