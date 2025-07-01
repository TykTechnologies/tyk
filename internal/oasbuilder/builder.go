package oasbuilder

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/common/option"
	"github.com/getkin/kin-openapi/openapi3"
)

type (
	// Builder OAS builder is responsible for providing methods for building valid OAS object.
	Builder struct {
		errors         []error
		oas            *oas.OAS
		xTykAPIGateway *oas.XTykAPIGateway
	}

	// EndpointBuilder OAS endpoint builder should be used for building endpoint and binding middlewares to it.
	EndpointBuilder struct {
		method string
		path   string
		errors []error
		op     *oas.Operation
	}

	// BuilderOption optional parameter should be used to define builder options in declarative way.
	BuilderOption = option.Option[Builder]

	// EndpointFactory factory method in which endpoint builder should be used.
	EndpointFactory func(b *EndpointBuilder)
)

const (
	minAllowedTimeFrameLength = time.Millisecond * 100

	// UpstreamUrlDefault default upstream url for OAS
	UpstreamUrlDefault = "http://localhost:3478/"
)

var (
	ErrMinRateLimitExceeded  = errors.New("minimum rate limit exceeded")
	ErrZeroAmountInRateLimit = errors.New("zero amount in rate limit")
)

// Build returns an allocated *OAS due to provided options
func Build(opts ...BuilderOption) (*oas.OAS, error) {
	return option.New(opts).Build(NewBuilder()).Build()
}

func NewBuilder() Builder {
	oasDef := oas.OAS{}

	oasDef.Paths = &openapi3.Paths{}

	xTykAPIGateway := oas.XTykAPIGateway{
		Info: oas.Info{},

		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Strip: true,
			},
		},

		Upstream: oas.Upstream{
			Proxy: &oas.Proxy{Enabled: true},
		},

		Middleware: &oas.Middleware{
			Operations: oas.Operations{},
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

func (b *Builder) Build() (*oas.OAS, error) {
	if len(b.errors) > 0 {
		return nil, errors.Join(b.errors...)
	}

	b.oas.SetTykExtension(b.xTykAPIGateway)

	return b.oas, nil
}

// WithTestDefaults sets defaults options
// to be sued for testing
func WithTestDefaults() BuilderOption {
	return combine(
		WithUpstreamUrl(UpstreamUrlDefault),
		WithListenPath("/test", true),
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

func newRateLimit(rate uint, duration time.Duration, enabled ...bool) (*oas.RateLimit, error) {
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

	return &oas.RateLimit{
		Enabled: enable,
		Rate:    int(rate),
		Per:     oas.ReadableDuration(duration),
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
		eb.operation().RateLimit = (*oas.RateLimitEndpoint)(rl)
	}

	return eb
}

func (eb *EndpointBuilder) Mock(fn func(mock *oas.MockResponse)) *EndpointBuilder {
	var mock oas.MockResponse
	mock.Enabled = true
	mock.Code = http.StatusOK
	mock.Body = "ok"

	fn(&mock)
	eb.operation().MockResponse = &mock

	return eb
}

func (eb *EndpointBuilder) operationId() string {
	return strings.ToLower(eb.path + eb.path)
}

func (eb *EndpointBuilder) operation() *oas.Operation {
	if eb.op == nil {
		eb.op = &oas.Operation{}
	}

	return eb.op
}

func (eb *EndpointBuilder) build(builder *Builder) {
	if len(eb.errors) > 0 {
		builder.appendErrors(eb.errors...)
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
		builder.oas.Paths.Set(eb.path, currentPath)
	}

	currentPath.SetOperation(eb.method, &openapi3.Operation{
		OperationID: eb.operationId(),
	})
}
