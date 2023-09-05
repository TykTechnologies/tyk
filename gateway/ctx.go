package gateway

import (
	"context"
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
)

func ctxSetAPISpec(r *http.Request, apiSpec *APISpec) {
	setCtxValue(r, ctx.APISpec, apiSpec)
}

func ctxGetAPISpec(c context.Context) *APISpec {
	if apiSpec := c.Value(ctx.APISpec); apiSpec != nil {
		return apiSpec.(*APISpec)
	}
	return nil
}

func ctxSetRetainHost(r *http.Request, retain bool) {
	setCtxValue(r, ctx.RetainHost, retain)
}

func ctxGetRetainHost(c context.Context) bool {
	retain, _ := c.Value(ctx.RetainHost).(bool)
	return retain
}
