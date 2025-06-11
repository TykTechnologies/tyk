package oas

import (
	"context"
	"errors"
	"fmt"
	tykheaders "github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/common/option"
	"github.com/getkin/kin-openapi/openapi3"
)

type (
	// Builder OAS builder is responsible for providing methods for building valid OAS object.
	Builder struct {
		errors         []error
		oas            *OAS
		xTykAPIGateway *XTykAPIGateway
	}

	// EndpointBuilder OAS endpoint builder should be used for building endpoint and binding middlewares to it.
	EndpointBuilder struct {
		method string
		path   string
		errors []error
		op     *Operation
	}

	// BuilderOption optional parameter should be used to define builder options in declarative way.
	BuilderOption = option.Option[Builder]

	// EndpointFactory factory method in which endpoint builder should be used.
	EndpointFactory func(b *EndpointBuilder)
)

const (
	minAllowedTimeFrameLength = time.Millisecond * 100
)

var (
	ErrMinRateLimitExceeded  = errors.New("minimum rate limit exceeded")
	ErrZeroAmountInRateLimit = errors.New("zero amount in rate limit")
	ErrEmptyApiSlug          = errors.New("empty api slug")
)

// NewOas returns an allocated *OAS due to provided options
func NewOas(opts ...BuilderOption) (*OAS, error) {
	return option.New(opts).Build(NewBuilder()).Build()
}

func NewBuilder() Builder {
	oasDef := OAS{}

	oasDef.OpenAPI = "3.0.0"
	oasDef.Info = &openapi3.Info{
		Title:   "Test API entity",
		Version: "1.0.0",
	}
	oasDef.Paths = openapi3.NewPaths()

	xTykAPIGateway := XTykAPIGateway{
		Info: Info{},

		Server: Server{
			ListenPath: ListenPath{
				Strip: true,
			},
		},

		Upstream: Upstream{
			Proxy: &Proxy{Enabled: true},
		},

		Middleware: &Middleware{
			Operations: Operations{},
		},
	}

	return Builder{
		errors:         nil,
		oas:            &oasDef,
		xTykAPIGateway: &xTykAPIGateway,
	}
}

func (b *Builder) appendErrors(errs ...error) {
	b.errors = append(b.errors, errs...)
}

func (b *Builder) Build() (*OAS, error) {
	if len(b.errors) > 0 {
		return nil, errors.Join(b.errors...)
	}

	b.oas.SetTykExtension(b.xTykAPIGateway)

	return b.oas, nil
}

// WithTestDefaults sets defaults options
// to be sued for testing
func WithTestDefaults(ctx context.Context, path string) BuilderOption {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add(tykheaders.ContentType, "application/json")
		w.WriteHeader(http.StatusNotFound)

		if _, err := w.Write([]byte(`{"message": "not found"}`)); err != nil {
			log.Errorf("failed to write response: %v", err)
		}
	}))

	go func() {
		<-ctx.Done()
		defer server.Close()
	}()

	return combine(
		withRandomId(),
		WithUpstreamUrl(server.URL),
		WithListenPath(path, true),
	)
}

func WithListenPath(path string, strip bool) BuilderOption {
	return func(b *Builder) {
		b.xTykAPIGateway.Server.ListenPath.Value = path
		b.xTykAPIGateway.Server.ListenPath.Strip = strip
	}
}

// combine combines some options
func combine(opts ...BuilderOption) BuilderOption {
	return func(b *Builder) {
		for _, apply := range opts {
			apply(b)
		}
	}
}

// WithUpstreamUrl defines upstream url
func WithUpstreamUrl(upstreamUrl string) BuilderOption {
	return func(b *Builder) {
		if _, err := url.Parse(upstreamUrl); err != nil {
			b.appendErrors(err)
			return
		}

		b.xTykAPIGateway.Upstream.URL = upstreamUrl
	}
}

func withRandomId() BuilderOption {
	return func(b *Builder) {
		b.xTykAPIGateway.Info.ID = uuid.New()
		b.xTykAPIGateway.Info.Name = uuid.New()
		b.xTykAPIGateway.Info.State.Active = true
		b.xTykAPIGateway.Info.State.Internal = false
	}
}

// WithGlobalRateLimit defines global rate limit
func WithGlobalRateLimit(rate uint, duration time.Duration, enabled ...bool) BuilderOption {
	return func(b *Builder) {
		if rl, err := newRateLimit(rate, duration, enabled...); err != nil {
			b.appendErrors(err)
			return
		} else {
			b.xTykAPIGateway.Upstream.RateLimit = rl
		}
	}
}

func newRateLimit(rate uint, duration time.Duration, enabled ...bool) (*RateLimit, error) {
	if duration < minAllowedTimeFrameLength {
		return nil, ErrMinRateLimitExceeded
	}

	if rate == 0 {
		return nil, ErrZeroAmountInRateLimit
	}

	var enable = true
	if len(enabled) > 0 {
		enable = enabled[0]
	}

	return &RateLimit{
		Enabled: enable,
		Rate:    int(rate),
		Per:     ReadableDuration(duration),
	}, nil
}

func withEndpoint(method, path string, fn EndpointFactory) BuilderOption {
	return func(b *Builder) {
		var eb = EndpointBuilder{
			method: method,
			path:   path,
		}

		fn(&eb)

		eb.build(b)
	}
}

// WithGet add get endpoint/path to OAS
func WithGet(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodGet, path, fn)
}

// WithPost add post endpoint/path to OAS
func WithPost(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodPost, path, fn)
}

// WithPut add put endpoint/path to OAS
func WithPut(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodPut, path, fn)
}

// WithDelete add delete endpoint/path to OAS
func WithDelete(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodDelete, path, fn)
}

func (eb *EndpointBuilder) RateLimit(amount uint, duration time.Duration, enabled ...bool) *EndpointBuilder {
	if rl, err := newRateLimit(amount, duration, enabled...); err != nil {
		eb.errors = append(eb.errors, err)
	} else {
		eb.operation().RateLimit = (*RateLimitEndpoint)(rl)
	}

	return eb
}

func (eb *EndpointBuilder) MockDefault() *EndpointBuilder {
	return eb.Mock(func(_ *MockResponse) {})
}

func (eb *EndpointBuilder) Mock(fn func(mock *MockResponse)) *EndpointBuilder {
	var mock MockResponse
	mock.Enabled = true
	mock.Code = http.StatusOK
	mock.Headers.Add(tykheaders.ContentType, "application/json")
	mock.Body = "{\"message\":\"ok\"}"

	fn(&mock)
	eb.operation().MockResponse = &mock

	return eb
}

func (eb *EndpointBuilder) operationId() string {
	return strings.TrimPrefix(strings.ToLower(eb.path+eb.method), "/")
}

func (eb *EndpointBuilder) operation() *Operation {
	if eb.op == nil {
		eb.op = &Operation{}
	}

	return eb.op
}

func (eb *EndpointBuilder) build(builder *Builder) {
	if len(eb.errors) > 0 {
		builder.appendErrors(eb.errors...)
		return
	}

	if builder.xTykAPIGateway.Server.ListenPath.Value == "" {
		builder.appendErrors(ErrEmptyApiSlug)
		return
	}

	if _, ok := builder.xTykAPIGateway.Middleware.Operations[eb.operationId()]; ok {
		builder.appendErrors(fmt.Errorf("duplicate operation id: %s", eb.operationId()))
		return
	}

	builder.xTykAPIGateway.Middleware.Operations[eb.operationId()] = eb.op

	currentPath := builder.oas.Paths.Find(eb.path)

	if currentPath == nil {
		currentPath = &openapi3.PathItem{}
	}

	emptyDescription := ""
	responses := openapi3.NewResponses()
	responses.Delete("default")
	responses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: &emptyDescription,
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{},
			},
		},
	})

	currentPath.SetOperation(eb.method, &openapi3.Operation{
		OperationID: eb.operationId(),
		Responses:   responses,
	})

	builder.oas.Paths.Set(eb.path, currentPath)
}
