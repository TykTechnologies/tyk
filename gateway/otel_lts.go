//go:build !v52
// +build !v52

package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/trace"
)

func registerTracerProvider(gw *Gateway) {}

func setupTracing(gwConfig *config.Config, tp otel.TracerProvider, spec *APISpec, chain http.Handler) http.Handler {
	// trace.IsEnabled = check if opentracing is enabled
	if trace.IsEnabled() {
		return trace.Handle(spec.Name, chain)
	}

	// keep original chain
	return chain
}

func (gw *Gateway) afterConfSetupFeatures(conf config.Config) {}
