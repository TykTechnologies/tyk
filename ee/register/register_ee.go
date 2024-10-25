//go:build ee || dev

package register

import (
	"github.com/TykTechnologies/tyk/ee/middleware/streams"

	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/model"
)

func init() {
	middleware.Add("ee:middleware:streaming", func(gw model.Gateway, base model.LoggerProvider, spec model.MergedAPI) model.Middleware {
		return streams.NewMiddleware(gw, base.Logger(), spec)
	})
}
