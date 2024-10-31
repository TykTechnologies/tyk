package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/internal/model"
)

type EventMetaDefault = model.EventMetaDefault

var (
	ctxData = httpctx.NewValue[map[string]any](ctx.ContextData)

	ctxGetData = ctxData.Get
	ctxSetData = ctxData.Set

	setContext = httputil.SetContext

	// how is type safety avoided: exhibit A, old school generics
	setCtxValue = func(h *http.Request, key, value any) {
		ctxvalue := httpctx.NewValue[any](key)
		h = ctxvalue.Set(h, value)
	}

	EncodeRequestToEvent = event.EncodeRequestToEvent
)
