package trace

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/TykTechnologies/tyk/request"
	opentracing "github.com/opentracing/opentracing-go"
)

var ErrManagerDisabled = errors.New("trace: trace is diabled")

// we use a global manager to avoid manual management as for our use case we
// only deal with on tracing server at a time.
var manager = NewManager(nil)

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

// OpenTracer manages initializing,storage and retrieving on multiple tracers
// based on service names.
type OpenTracer struct {
	mu       sync.RWMutex
	services map[string]Tracer
	log      Logger
	enabled  atomic.Value
	config   Config
}

type Config struct {
	Name string
	Opts map[string]interface{}
}

// NewManager returns a new opentrace manager. If log is not nil it will be used
// to log errors and info by the manager.
func NewManager(log Logger) *OpenTracer {
	return &OpenTracer{log: log, services: make(map[string]Tracer)}
}

// Get returns a tracer for a given service, it returns a NoopTracer if there is
// no tracer for the service found.
func (o *OpenTracer) Get(service string) Tracer {
	o.mu.RLock()
	t, ok := o.services[service]
	o.mu.RUnlock()
	if !ok {
		if o.log != nil {
			o.log.Info(service, "not found")
		}
		return NoopTracer{}
	}
	return t
}

// Get returns a tracer stored on the global trace manager.
func Get(service string) Tracer {
	return manager.Get(service)
}

// GetOk like Get but instead of returning NoopTracer for missing tracer it
// returns nil and false when the service tracer wasn't found.
func (o *OpenTracer) GetOk(service string) (Tracer, bool) {
	o.mu.RLock()
	t, ok := o.services[service]
	o.mu.RUnlock()
	return t, ok
}

// Set saves tr using service as key on o.
func (o *OpenTracer) Set(service string, tr Tracer) {
	o.mu.Lock()
	o.services[service] = tr
	o.mu.Unlock()
}

// Close calls Close on the active tracer.
func (o *OpenTracer) Close() error {
	o.mu.RLock()
	for _, v := range o.services {
		if err := v.Close(); err != nil {
			return err
		}
	}
	o.mu.RUnlock()
	o.mu.Lock()
	o.services = make(map[string]Tracer)
	o.mu.Unlock()
	return nil
}

// Close calls Close on the global tace manager.
func Close() error {
	return manager.Close()
}

// IsEnabled returns true if the manager is enabled.
func (o *OpenTracer) IsEnabled() bool {
	ok := o.enabled.Load()
	if ok != nil {
		return ok.(bool)
	}
	return false
}

// IsEnabled returns true if the global trace manager is enabled.
func IsEnabled() bool {
	return manager.IsEnabled()
}

// Enable sets o to enabled state.
func (o *OpenTracer) Enable() {
	o.enabled.Store(true)
}

// Enable sets the global manager to enabled.
func Enable() {
	manager.Enable()
}

// Disable sets o to disabled state.
func (o *OpenTracer) Disable() {
	o.enabled.Store(false)
}

// Disable disables the global trace manager.
func Disable() {
	manager.Disable()
}

// SetLogger sets log as the default logger for o.
func (o *OpenTracer) SetLogger(log Logger) {
	o.mu.Lock()
	o.log = log
	o.mu.Unlock()
}

// AddTracer initializes a tracer based on the configuration stored in o for the
// given service name and caches. This does donthing when there is already a
// tracer for the given service.
func (o *OpenTracer) AddTracer(service string) error {
	_, ok := o.GetOk(service)
	if !ok {
		tr, err := Init(o.config.Name, service, o.config.Opts, o.log)
		if err != nil {
			if o.log != nil {
				o.log.Errorf("%v", err)
			}
			return err
		}
		o.Set(service, tr)
	}
	return nil
}

// AddTracer initialize a tracer for the service.
func AddTracer(service string) error {
	if !manager.IsEnabled() {
		return ErrManagerDisabled
	}
	return manager.AddTracer(service)
}

func SetLogger(log Logger) {
	manager.SetLogger(log)
}

func (o *OpenTracer) SetupTracing(name string, opts map[string]interface{}) {
	o.config.Name = name
	o.config.Opts = opts
}

func SetupTracing(name string, opts map[string]interface{}) {
	manager.SetupTracing(name, opts)
	manager.Enable()
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
