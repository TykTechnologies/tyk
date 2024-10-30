package gateway

import (
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/internal/httpctx"
	"github.com/TykTechnologies/tyk/internal/model"
)

type EventMetaDefault = model.EventMetaDefault

var (
	ctxData = httpctx.NewValue[map[string]any](ctx.ContextData)

	ctxGetData = ctxData.Get
	ctxSetData = ctxData.Set
)
