package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/service/core"
)

type EventMetaDefault = model.EventMetaDefault

type CtxData = map[string]any

const (
	ctxDataKeyRateLimitLimit     = "rate_limit_limit"
	ctxDataKeyRateLimitRemaining = "rate_limit_remaining"
	ctxDataKeyRateLimitReset     = "rate_limit_reset"

	ctxDataKeyQuotaLimit     = "quota_limit"
	ctxDataKeyQuotaRemaining = "quota_remaining"
	ctxDataKeyQuotaReset     = "quota_reset"
)

var (
	ctxData = httpctx.NewValue[CtxData](ctx.ContextData)

	ctxGetData = ctxData.Get
	ctxSetData = ctxData.Set

	setContext = core.SetContext

	// how is type safety avoided: exhibit A, old school generics
	setCtxValue = func(h *http.Request, key, value any) {
		ctxvalue := httpctx.NewValue[any](key)
		h = ctxvalue.Set(h, value)
	}

	EncodeRequestToEvent = event.EncodeRequestToEvent
)

func ctxGetOrCreateData(r *http.Request) CtxData {
	data := ctxGetData(r)

	if data == nil {
		data = CtxData{}
		ctxSetData(r, data)
	}

	return data
}
