//go:build v52
// +build v52

package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/trace"
)

func registerTracerProvider(gw *Gateway) {
	otelConfig := gw.GetConfig().OpenTelemetry
	gw.TracerProvider = otel.InitOpenTelemetry(
		gw.ctx,
		mainLog.Logger,
		&otelConfig,
		gw.GetNodeID(),
		VERSION,
		gw.GetConfig().SlaveOptions.UseRPC,
		gw.GetConfig().SlaveOptions.GroupID,
		gw.GetConfig().DBAppConfOptions.NodeIsSegmented,
		gw.GetConfig().DBAppConfOptions.Tags)
}

func setupTracing(gwConfig *config.Config, tp otel.TracerProvider, spec *APISpec, chain http.Handler) http.Handler {
	// trace.IsEnabled = check if opentracing is enabled
	if trace.IsEnabled() {
		return trace.Handle(spec.Name, chain)
	}

	// check if opentelemetry is enabled
	if gwConfig.OpenTelemetry.Enabled {
		spanAttrs := []otel.SpanAttribute{}
		spanAttrs = append(spanAttrs, otel.ApidefSpanAttributes(spec.APIDefinition)...)
		return otel.HTTPHandler(spec.Name, chain, tp, spanAttrs...)
	}

	// keep original chain
	return chain
}

func (gw *Gateway) afterConfSetupFeatures(conf config.Config) {
	if conf.OpenTelemetry.Enabled {
		if conf.OpenTelemetry.ResourceName == "" {
			conf.OpenTelemetry.ResourceName = config.DefaultOTelResourceName
		}

		conf.OpenTelemetry.SetDefaults()
	}
}
