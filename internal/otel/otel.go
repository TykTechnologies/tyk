package otel

import (
	"context"

	"github.com/sirupsen/logrus"

	otelconfig "github.com/TykTechnologies/opentelemetry/config"
	semconv "github.com/TykTechnologies/opentelemetry/semconv/v1.0.0"
	tyktrace "github.com/TykTechnologies/opentelemetry/trace"
	"github.com/TykTechnologies/tyk/apidef"
)

// general type aliases
type (
	TracerProvider = tyktrace.Provider

	Config = otelconfig.OpenTelemetry

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
func InitOpenTelemetry(ctx context.Context, logger *logrus.Logger, gwConfig *Config, id string, version string) TracerProvider {

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

func GatewaySpanAttributes(gwID string, isHybrid bool, groupID string, isSegmented bool, segmentTags []string) []SpanAttribute {
	attrs := []SpanAttribute{
		semconv.TykGWID(gwID),
		semconv.TykGWHybrid(isHybrid),
	}

	if isHybrid {
		attrs = append(attrs, semconv.TykHybridGWGroupID(groupID))
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
