package oasbuilder

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/common/option"
	tykheaders "github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/getkin/kin-openapi/openapi3"
)

type (
	Builder struct {
		errors         []error
		oas            *oas.OAS
		xTykAPIGateway *oas.XTykAPIGateway
	}

	EndpointBuilder struct {
		method string
		path   string
		errors []error
		op     *oas.Operation
	}

	BuilderOption = option.Option[Builder]

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

func Build(opts ...BuilderOption) (*oas.OAS, error) {
	return option.New(opts).Build(New()).Build()
}

func New() Builder {
	oasDef := oas.OAS{}

	oasDef.OpenAPI = "3.0.0"
	oasDef.Info = &openapi3.Info{
		Title:   "Test API entity",
		Version: "1.0.0",
	}
	oasDef.Paths = openapi3.NewPaths()

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

func WithTestListenPathAndUpstream(path, upstreamUrl string) BuilderOption {
	return combine(
		withRandomId(),
		WithUpstreamUrl(upstreamUrl),
		WithListenPath(path, true),
	)
}

func WithListenPath(path string, strip bool) BuilderOption {
	return func(b *Builder) {
		b.xTykAPIGateway.Server.ListenPath.Value = path
		b.xTykAPIGateway.Server.ListenPath.Strip = strip
	}
}

func combine(opts ...BuilderOption) BuilderOption {
	return func(b *Builder) {
		for _, apply := range opts {
			apply(b)
		}
	}
}

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

func WithGet(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodGet, path, fn)
}

func WithPost(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodPost, path, fn)
}

func WithPut(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodPut, path, fn)
}

func WithDelete(path string, fn EndpointFactory) BuilderOption {
	return withEndpoint(http.MethodDelete, path, fn)
}

// RateLimit adds rate limit middleware to current endpoint.
func (eb *EndpointBuilder) RateLimit(amount uint, duration time.Duration, enabled ...bool) *EndpointBuilder {
	if rl, err := newRateLimit(amount, duration, enabled...); err != nil {
		eb.errors = append(eb.errors, err)
	} else {
		eb.operation().RateLimit = (*oas.RateLimitEndpoint)(rl)
	}

	return eb
}

func (eb *EndpointBuilder) TransformResponseHeaders(factory func(*oas.TransformHeaders)) *EndpointBuilder {
	op := eb.operation().TransformResponseHeaders

	if op == nil {
		op = &oas.TransformHeaders{Enabled: true}
		eb.operation().TransformResponseHeaders = op
	}

	factory(op)

	return eb
}

func (eb *EndpointBuilder) TransformRequestHeaders(factory func(*oas.TransformHeaders)) *EndpointBuilder {
	op := eb.operation().TransformRequestHeaders

	if op == nil {
		op = &oas.TransformHeaders{Enabled: true}
		eb.operation().TransformRequestHeaders = op
	}

	factory(op)

	return eb
}

func (eb *EndpointBuilder) TransformResponseBody(factory func(*oas.TransformBody)) *EndpointBuilder {
	op := eb.operation().TransformResponseBody

	if op == nil {
		op = &oas.TransformBody{Enabled: true}
		eb.operation().TransformResponseBody = op
	}

	factory(op)

	return eb
}

// TransformResponseBodyJson defines json template
func (eb *EndpointBuilder) TransformResponseBodyJson(tpl string) *EndpointBuilder {
	return eb.TransformResponseBody(func(body *oas.TransformBody) {
		body.Format = apidef.RequestJSON
		body.Enabled = true
		body.Body = base64.StdEncoding.EncodeToString([]byte(tpl))
	})
}

func (eb *EndpointBuilder) MockDefault() *EndpointBuilder {
	return eb.Mock(func(_ *oas.MockResponse) {})
}

func (eb *EndpointBuilder) Mock(fn func(mock *oas.MockResponse)) *EndpointBuilder {
	var mock oas.MockResponse
	mock.Enabled = true
	mock.Code = http.StatusOK
	mock.Headers.Add(tykheaders.ContentType, tykheaders.ApplicationJSON)
	mock.Body = `{"message":"ok"}`

	fn(&mock)
	eb.operation().MockResponse = &mock

	return eb
}

func (eb *EndpointBuilder) operationId() string {
	return strings.TrimPrefix(strings.ToLower(eb.path+eb.method), "/")
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
				tykheaders.ApplicationJSON: &openapi3.MediaType{},
			},
		},
	})

	currentPath.SetOperation(eb.method, &openapi3.Operation{
		OperationID: eb.operationId(),
		Responses:   responses,
	})

	builder.oas.Paths.Set(eb.path, currentPath)
}
