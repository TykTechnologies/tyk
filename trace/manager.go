package trace

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	opentracing "github.com/opentracing/opentracing-go"

	"github.com/TykTechnologies/tyk/request"
)

// ErrManagerDisabled is returned when trying to use global trace manager when
// it is disabled.
var ErrManagerDisabled = errors.New("trace: trace is diabled")

// This stores a map of opentracer configurations.
var manager = &sync.Map{}

// This stores a map of service name to  initialized Tracer implementation.
var services = &sync.Map{}

// Stores status of tracing.
var enabled atomic.Value
var logger Logger = StdLogger{}
var initializer = Init

// serviceID key used to store the service name in request context.Context.
type serviceID = struct{}

// SetServiceID returns context with service assigned to it.
func SetServiceID(ctx context.Context, service string) context.Context {
	return context.WithValue(ctx, serviceID{}, service)
}

// GetServiceID returns service name attched to context returns an empty string
// if the service name key is not found.
func GetServiceID(ctx context.Context) string {
	if v := ctx.Value(serviceID{}); v != nil {
		return v.(string)
	}
	return ""
}

// Logger defines api for logging messages by the OpenTracer struct. This is a
// workaround to avoid trying this to logrus
type Logger interface {
	Errorf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
}

type StdLogger struct{}

func (StdLogger) Errorf(format string, args ...interface{}) {
	log.Println("[ERROR] trace: ", fmt.Sprintf(format, args...))
}
func (StdLogger) Infof(format string, args ...interface{}) {
	log.Println("[INFO] trace: ", fmt.Sprintf(format, args...))
}

func (StdLogger) Info(args ...interface{}) {
	log.Println("[INFO] trace: ", fmt.Sprint(args...))
}

func (StdLogger) Error(args ...interface{}) {
	log.Println("[ERROR] trace: ", fmt.Sprint(args...))
}

type Config struct {
	Name string
	Opts map[string]interface{}
}

// Get returns a tracer stored on the global trace manager.
func Get(service string) Tracer {
	if t, ok := services.Load(service); ok {
		return t.(Tracer)
	}
	return NoopTracer{}
}

// Close calls Close on the global tace manager.
func Close() error {
	var s []string
	services.Range(func(k, v interface{}) bool {
		s = append(s, k.(string))
		v.(Tracer).Close()
		return true
	})
	for _, v := range s {
		services.Delete(v)
	}
	Disable()
	return nil
}

// IsEnabled returns true if the global trace manager is enabled.
func IsEnabled() bool {
	if v := enabled.Load(); v != nil {
		return v.(bool)
	}
	return false
}

// Enable sets the global manager to enabled.
func Enable() {
	enabled.Store(true)
}

// Disable disables the global trace manager.
func Disable() {
	enabled.Store(false)
}

// AddTracer initialize a tracer for the service.
func AddTracer(tracer, service string) error {
	if !IsEnabled() {
		return ErrManagerDisabled
	}
	if _, ok := services.Load(service); !ok {
		if v, ok := manager.Load(tracer); ok {
			c := v.(Config)
			tr, err := initializer(c.Name, service, c.Opts, StdLogger{})
			if err != nil {
				return err
			}
			services.Store(service, tr)
		}
	}
	return nil
}

func SetLogger(log Logger) {
	logger = log
}

func SetInit(fn InitFunc) {
	initializer = fn
}

func SetupTracing(name string, opts map[string]interface{}) {
	// We are using empty string as key since we only work with one opentracer at a
	// time hence the default.
	manager.Store("", Config{
		Name: name,
		Opts: opts,
	})
	enabled.Store(true)
}

func Root(service string, r *http.Request) (opentracing.Span, *http.Request) {
	tr := Get(service)
	mainCtx, err := Extract(tr, r.Header)
	tags := opentracing.Tags{
		"from_ip":  request.RealIP(r),
		"method":   r.Method,
		"endpoint": r.URL.Path,
		"raw_url":  r.URL.String(),
		"size":     strconv.Itoa(int(r.ContentLength)),
	}
	if err != nil {
		// TODO log this error?
		// We just create a new span here so the log should be a warning.
		span, ctx := opentracing.StartSpanFromContextWithTracer(r.Context(),
			tr,
			service, tags)
		return span, r.WithContext(SetServiceID(ctx, service))
	}
	span, ctx := opentracing.StartSpanFromContextWithTracer(r.Context(),
		tr,
		service,
		opentracing.ChildOf(mainCtx), tags)
	return span, r.WithContext(SetServiceID(ctx, service))
}

// Span creates a new span for the given ops. If tracing is disabled in this ctx
// then a noop span is created and the same ctx is returned.
//
// Note that the returned context contains the returned span as active span. So
// any spans created form the returned context will be children of the returned
// span.
func Span(ctx context.Context, ops string, opts ...opentracing.StartSpanOption) (opentracing.Span, context.Context) {
	return opentracing.StartSpanFromContextWithTracer(ctx,
		Get(GetServiceID(ctx)),
		ops, opts...)
}

func Extract(tr Tracer, h http.Header) (opentracing.SpanContext, error) {
	return tr.Extract(
		opentracing.HTTPHeaders,
		opentracing.HTTPHeadersCarrier(h),
	)
}

func ExtractFromContext(ctx context.Context, h http.Header) (opentracing.SpanContext, error) {
	return Extract(Get(GetServiceID(ctx)), h)
}

func Inject(service string, span opentracing.Span, h http.Header) error {
	tr := Get(service)
	return tr.Inject(
		span.Context(),
		opentracing.HTTPHeaders,
		opentracing.HTTPHeadersCarrier(h),
	)
}

func InjectFromContext(ctx context.Context, span opentracing.Span, h http.Header) error {
	return Inject(GetServiceID(ctx), span, h)
}
