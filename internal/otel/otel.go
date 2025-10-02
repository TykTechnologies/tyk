package otel

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
	"github.com/TykTechnologies/tyk/apidef"
)

// general type aliases
type (
	TracerProvider = tyktrace.Provider

	OpenTelemetry = otelconfig.OpenTelemetry

	Sampling = otelconfig.Sampling

	SpanAttribute = tyktrace.Attribute

	Span = tyktrace.Span
)

// HTTP Handlers
var (
	HTTPHandler = tyktrace.NewHTTPHandler

	HTTPRoundTripper = tyktrace.NewHTTPTransport
)

// span const
const (
	SPAN_STATUS_OK    = tyktrace.SPAN_STATUS_OK
	SPAN_STATUS_ERROR = tyktrace.SPAN_STATUS_ERROR
	SPAN_STATUS_UNSET = tyktrace.SPAN_STATUS_UNSET
)

const (
	NON_VERSIONED = "Non Versioned"
)

func ContextWithSpan(ctx context.Context, span tyktrace.Span) context.Context {
	return tyktrace.ContextWithSpan(ctx, span)
}

// InitOpenTelemetry initializes OpenTelemetry - it returns a TracerProvider
// which can be used to create a tracer. If OpenTelemetry is disabled or misconfigured,
// a NoopProvider is returned.
func InitOpenTelemetry(ctx context.Context, logger *logrus.Logger, gwConfig *OpenTelemetry, id string, version string,
	useRPC bool, groupID string, isSegmented bool, segmentTags []string) TracerProvider {

	traceLogger := logger.WithFields(logrus.Fields{
		"exporter":           gwConfig.Exporter,
		"endpoint":           gwConfig.Endpoint,
		"connection_timeout": gwConfig.ConnectionTimeout,
	})

	provider, errOtel := tyktrace.NewProvider(
		tyktrace.WithContext(ctx),
		tyktrace.WithConfig(gwConfig),
		tyktrace.WithLogger(traceLogger),
		tyktrace.WithServiceID(id),
		tyktrace.WithServiceVersion(version),
		tyktrace.WithHostDetector(),
		tyktrace.WithContainerDetector(),
		tyktrace.WithProcessDetector(),
		tyktrace.WithCustomResourceAttributes(GatewayResourceAttributes(
			id,
			useRPC,
			groupID,
			isSegmented,
			segmentTags,
		)...),
	)

	if errOtel != nil {
		logger.Errorf("Initializing OpenTelemetry %s", errOtel)
	}

	return provider
}

// Span attributes related functions
func ApidefSpanAttributes(apidef *apidef.APIDefinition) []SpanAttribute {
	attrs := []SpanAttribute{
		semconv.TykAPIName(apidef.Name),
		semconv.TykAPIOrgID(apidef.OrgID),
		semconv.TykAPIID(apidef.APIID),
		semconv.TykAPIListenPath(apidef.Proxy.ListenPath),
	}

	if !apidef.TagsDisabled {
		tags := apidef.Tags
		tags = append(tags, apidef.TagHeaders...)

		attrs = append(attrs, semconv.TykAPITags(tags...))
	}

	return attrs
}

func GatewayResourceAttributes(gwID string, isDataplane bool, groupID string, isSegmented bool, segmentTags []string) []SpanAttribute {
	attrs := []SpanAttribute{
		semconv.TykGWID(gwID),
		semconv.TykGWDataplane(isDataplane),
	}

	if isDataplane {
		attrs = append(attrs, semconv.TykDataplaneGWGroupID(groupID))
	}

	if isSegmented {
		attrs = append(attrs, semconv.TykGWSegmentTags(segmentTags...))
	}

	return attrs
}

func APIVersionAttribute(version string) SpanAttribute {
	if version == "" {
		version = NON_VERSIONED
	}
	return semconv.TykAPIVersion(version)
}

var APIKeyAttribute = semconv.TykAPIKey

var APIKeyAliasAttribute = semconv.TykAPIKeyAlias

var OAuthClientIDAttribute = semconv.TykOauthID

func SpanFromContext(ctx context.Context) tyktrace.Span {
	return tyktrace.SpanFromContext(ctx)
}

func AddTraceID(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	span := SpanFromContext(ctx)
	if span.SpanContext().HasTraceID() {
		traceID := span.SpanContext().TraceID().String()

		w.Header().Set("X-Tyk-Trace-Id", traceID)

		r.Header.Set("X-Tyk-Trace-Id", traceID)
	}
}
