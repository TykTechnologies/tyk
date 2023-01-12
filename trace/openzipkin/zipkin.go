package openzipkin

import (
	"errors"
	"fmt"
	"strings"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/log"
	zipkin "github.com/openzipkin/zipkin-go"
	"github.com/openzipkin/zipkin-go/model"
	"github.com/openzipkin/zipkin-go/propagation/b3"
	"github.com/openzipkin/zipkin-go/reporter"
	"github.com/openzipkin/zipkin-go/reporter/http"

	"github.com/TykTechnologies/tyk/config"
)

var _ opentracing.Tracer = (*zipkinTracer)(nil)
var _ opentracing.SpanContext = (*spanContext)(nil)
var _ opentracing.Span = (*Span)(nil)

const Name = "zipkin"

type Span struct {
	span zipkin.Span
	tr   *zipkinTracer
}

func (s Span) Context() opentracing.SpanContext {
	return spanContext{s.span.Context()}
}

func (s Span) Finish() {
	s.span.Finish()
}

func (s Span) FinishWithOptions(opts opentracing.FinishOptions) {
	s.span.Finish()
}

func (s Span) SetOperationName(operationName string) opentracing.Span {
	s.span.SetName(operationName)
	return s
}

func (s Span) SetTag(key string, value interface{}) opentracing.Span {
	s.span.Tag(key, fmt.Sprint(value))
	return s
}

func (s Span) LogFields(fields ...log.Field) {
	now := time.Now()
	lg := &logEncoder{h: func(key string, value interface{}) {
		s.span.Annotate(now, fmt.Sprintf("%s %s", key, value))
	}}
	for _, field := range fields {
		field.Marshal(lg)
	}
}

type logEncoder struct {
	h func(string, interface{})
}

func (e *logEncoder) emit(key string, value interface{}) {
	if e.h != nil {
		e.h(key, value)
	}
}
func (e *logEncoder) EmitString(key, value string)             { e.emit(key, value) }
func (e *logEncoder) EmitBool(key string, value bool)          { e.emit(key, value) }
func (e *logEncoder) EmitInt(key string, value int)            { e.emit(key, value) }
func (e *logEncoder) EmitInt32(key string, value int32)        { e.emit(key, value) }
func (e *logEncoder) EmitInt64(key string, value int64)        { e.emit(key, value) }
func (e *logEncoder) EmitUint32(key string, value uint32)      { e.emit(key, value) }
func (e *logEncoder) EmitUint64(key string, value uint64)      { e.emit(key, value) }
func (e *logEncoder) EmitFloat32(key string, value float32)    { e.emit(key, value) }
func (e *logEncoder) EmitFloat64(key string, value float64)    { e.emit(key, value) }
func (e *logEncoder) EmitObject(key string, value interface{}) { e.emit(key, value) }
func (e *logEncoder) EmitLazyLogger(value log.LazyLogger)      {}

func (s Span) LogKV(alternatingKeyValues ...interface{})                   {}
func (s Span) SetBaggageItem(restrictedKey, value string) opentracing.Span { return s }
func (Span) BaggageItem(restrictedKey string) string                       { return "" }
func (s Span) Tracer() opentracing.Tracer                                  { return s.tr }
func (s Span) LogEvent(event string)                                       {}
func (s Span) LogEventWithPayload(event string, payload interface{})       {}
func (s Span) Log(data opentracing.LogData)                                {}

type spanContext struct {
	model.SpanContext
}

func (spanContext) ForeachBaggageItem(handler func(k, v string) bool) {}

type extractor interface {
	extract(carrier interface{}) (spanContext, error)
}

var emptyContext spanContext

func extractHTTPHeader(carrier interface{}) (spanContext, error) {
	c, ok := carrier.(opentracing.HTTPHeadersCarrier)
	if !ok {
		return emptyContext, opentracing.ErrInvalidCarrier
	}
	var (
		traceIDHeader      string
		spanIDHeader       string
		parentSpanIDHeader string
		sampledHeader      string
		flagsHeader        string
		singleHeader       string
	)
	err := c.ForeachKey(func(key, val string) error {
		switch strings.ToLower(key) {
		case b3.TraceID:
			traceIDHeader = val
		case b3.SpanID:
			spanIDHeader = val
		case b3.ParentSpanID:
			parentSpanIDHeader = val
		case b3.Sampled:
			sampledHeader = val
		case b3.Flags:
			flagsHeader = val
		case b3.Context:
			singleHeader = val
		}
		return nil
	})
	if err != nil {
		return emptyContext, err
	}
	if singleHeader != "" {
		ctx, err := b3.ParseSingleHeader(singleHeader)
		if err != nil {
			return emptyContext, err
		}
		return spanContext{*ctx}, nil
	}
	ctx, err := b3.ParseHeaders(
		traceIDHeader, spanIDHeader, parentSpanIDHeader,
		sampledHeader, flagsHeader,
	)
	if err != nil {
		return emptyContext, err
	}
	return spanContext{*ctx}, nil
}

type extractorFn func(carrier interface{}) (spanContext, error)

func (fn extractorFn) extract(carrier interface{}) (spanContext, error) {
	return fn(carrier)
}

type injector interface {
	inject(ctx spanContext, carrier interface{}) error
}

func injectHTTPHeaders(ctx spanContext, carrier interface{}) error {
	c, ok := carrier.(opentracing.HTTPHeadersCarrier)
	if !ok {
		return opentracing.ErrInvalidCarrier
	}
	if ctx == emptyContext {
		return nil
	}
	c.Set(b3.Context, b3.BuildSingleHeader(ctx.SpanContext))
	return nil
}

type injectorFn func(ctx spanContext, carrier interface{}) error

func (fn injectorFn) inject(ctx spanContext, carrier interface{}) error {
	return fn(ctx, carrier)
}

type zipkinTracer struct {
	zip        *zipkin.Tracer
	extractors map[interface{}]extractor
	injectors  map[interface{}]injector
}

func NewTracer(zip *zipkin.Tracer) *zipkinTracer {
	return &zipkinTracer{
		zip: zip,
		extractors: map[interface{}]extractor{
			opentracing.HTTPHeaders: extractorFn(extractHTTPHeader),
		},
		injectors: map[interface{}]injector{
			opentracing.HTTPHeaders: injectorFn(injectHTTPHeaders),
		},
	}
}

func (z *zipkinTracer) StartSpan(operationName string, opts ...opentracing.StartSpanOption) opentracing.Span {
	var o []zipkin.SpanOption
	if len(opts) > 0 {
		var os opentracing.StartSpanOptions
		for _, opt := range opts {
			opt.Apply(&os)
		}
		if len(os.Tags) > 0 {
			t := make(map[string]string)
			for k, v := range os.Tags {
				t[k] = fmt.Sprint(v)
			}
			o = append(o, zipkin.Tags(t))
		}
		for _, ref := range os.References {
			switch ref.Type {
			case opentracing.ChildOfRef:
				sp := ref.ReferencedContext.(spanContext)
				o = append(o, zipkin.Parent(
					sp.SpanContext,
				))
			}
		}
	}
	sp := z.zip.StartSpan(operationName, o...)
	return Span{tr: z, span: sp}
}

func (z *zipkinTracer) Extract(format interface{}, carrier interface{}) (opentracing.SpanContext, error) {
	if x, ok := z.extractors[format]; ok {
		return x.extract(carrier)
	}
	return nil, opentracing.ErrUnsupportedFormat
}

func (z *zipkinTracer) Inject(ctx opentracing.SpanContext, format interface{}, carrier interface{}) error {
	c, ok := ctx.(spanContext)
	if !ok {
		return opentracing.ErrInvalidSpanContext
	}
	if x, ok := z.injectors[format]; ok {
		return x.inject(c, carrier)
	}
	return opentracing.ErrUnsupportedFormat
}

type Tracer struct {
	opentracing.Tracer
	reporter.Reporter
}

func (Tracer) Name() string {
	return Name
}

func Init(service string, opts map[string]interface{}) (*Tracer, error) {
	c, err := Load(opts)
	if err != nil {
		return nil, err
	}
	if c.Reporter.URL == "" {
		return nil, errors.New("zipkin: missing url")
	}
	r := http.NewReporter(c.Reporter.URL)
	endpoint, err := zipkin.NewEndpoint(service, "")
	if err != nil {
		return nil, err
	}
	sampler, err := getSampler(c.Sampler)
	if err != nil {
		return nil, err
	}
	tr, err := zipkin.NewTracer(r,
		zipkin.WithLocalEndpoint(endpoint),
		zipkin.WithSampler(sampler),
	)
	if err != nil {
		return nil, err
	}
	return &Tracer{Tracer: NewTracer(tr), Reporter: r}, nil
}

func getSampler(s config.Sampler) (zipkin.Sampler, error) {
	if s.Name == "" {
		return zipkin.AlwaysSample, nil
	}
	switch s.Name {
	case "boundary":
		return zipkin.NewBoundarySampler(s.Rate, s.Salt)
	case "count":
		return zipkin.NewCountingSampler(s.Rate)
	case "mod":
		return zipkin.NewModuloSampler(s.Mod), nil
	}
	return nil, fmt.Errorf("zipkin: unknown sampler %s", s.Name)
}
