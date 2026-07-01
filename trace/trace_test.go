package trace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	opentracing "github.com/opentracing/opentracing-go"
	opentracinglog "github.com/opentracing/opentracing-go/log"

	"github.com/TykTechnologies/tyk/trace/jaeger"
	"github.com/TykTechnologies/tyk/trace/openzipkin"
)

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// STK-REQ-090:STK-REQ-090-AC-01:acceptance
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:determinism:nominal
func TestServiceIDContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{
			name: "returns empty service when unset",
			ctx:  context.Background(),
		},
		{
			name: "returns stored service",
			ctx:  SetServiceID(context.Background(), "gateway"),
			want: "gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetServiceID(tt.ctx); got != tt.want {
				t.Fatalf("expected %q got %q", tt.want, got)
			}
		})
	}
}

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:error_handling:nominal
// SW-REQ-165:error_handling:negative
// SW-REQ-165:determinism:nominal
// STK-REQ-090:error_handling:negative
func TestManagerStateAndTracerRegistration(t *testing.T) {
	resetTraceGlobals(t)

	if IsEnabled() {
		t.Fatal("expected tracing disabled by default")
	}
	if _, ok := Get("missing").(NoopTracer); !ok {
		t.Fatal("expected no-op tracer for missing service")
	}
	if err := AddTracer("", "svc"); !errors.Is(err, ErrManagerDisabled) {
		t.Fatalf("expected manager disabled error got %v", err)
	}

	tracer := &recordingTracer{name: "configured"}
	var calls int
	SetInit(func(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error) {
		calls++
		if name != "configured" {
			t.Fatalf("expected configured name got %q", name)
		}
		if service != "svc" {
			t.Fatalf("expected service svc got %q", service)
		}
		if got := opts["sample"]; got != "value" {
			t.Fatalf("expected opts to be forwarded got %#v", opts)
		}
		if _, ok := logger.(StdLogger); !ok {
			t.Fatalf("expected StdLogger got %T", logger)
		}
		return tracer, nil
	})

	SetupTracing("configured", map[string]interface{}{"sample": "value"})
	if !IsEnabled() {
		t.Fatal("expected tracing enabled")
	}
	if err := AddTracer("", "svc"); err != nil {
		t.Fatal(err)
	}
	if err := AddTracer("", "svc"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected initializer once got %d", calls)
	}
	if got := Get("svc"); got != tracer {
		t.Fatal("expected registered tracer")
	}

	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if tracer.closeCount != 1 {
		t.Fatalf("expected tracer close got %d", tracer.closeCount)
	}
	if IsEnabled() {
		t.Fatal("expected close to disable tracing")
	}
	if _, ok := Get("svc").(NoopTracer); !ok {
		t.Fatal("expected close to remove registered tracer")
	}
}

// Reproduces: KI-TRACE-CLOSE-IGNORES-TRACER-ERROR
// Verifies: SYS-REQ-178
func TestKnownIssue_CloseIgnoresTracerCloseErrors(t *testing.T) {
	resetTraceGlobals(t)
	tracer := &recordingTracer{name: "failing", closeErr: errors.New("close failed")}
	services.Store("svc", tracer)

	if err := Close(); err != nil {
		t.Fatalf("expected current implementation to ignore close error, got %v", err)
	}
	if tracer.closeCount != 1 {
		t.Fatalf("expected close to be called once got %d", tracer.closeCount)
	}
}

// Reproduces: KI-TRACE-ADDTRACER-IGNORES-CONFIGURED-LOGGER
// Verifies: SYS-REQ-178
func TestKnownIssue_AddTracerIgnoresConfiguredLogger(t *testing.T) {
	resetTraceGlobals(t)

	configuredLogger := &recordingManagerLogger{}
	var gotLogger Logger
	SetLogger(configuredLogger)
	SetInit(func(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error) {
		gotLogger = logger
		return &recordingTracer{name: "svc"}, nil
	})
	SetupTracing("configured", nil)

	if err := AddTracer("", "svc"); err != nil {
		t.Fatal(err)
	}
	if gotLogger == configuredLogger {
		t.Fatal("expected current implementation to ignore configured logger")
	}
	if _, ok := gotLogger.(StdLogger); !ok {
		t.Fatalf("expected StdLogger in current implementation got %T", gotLogger)
	}
}

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:encoding_safety:nominal
// SW-REQ-165:error_handling:nominal
// SW-REQ-165:error_handling:negative
// SW-REQ-165:determinism:nominal
func TestSpanExtractAndInjectHelpers(t *testing.T) {
	resetTraceGlobals(t)

	tracer := &recordingTracer{name: "svc"}
	services.Store("svc", tracer)
	ctx := SetServiceID(context.Background(), "svc")
	header := http.Header{"B3": {"trace-span"}}

	span, spanCtx := Span(ctx, "child")
	if span == nil {
		t.Fatal("expected span")
	}
	if GetServiceID(spanCtx) != "svc" {
		t.Fatal("expected child span context to retain service id")
	}
	if tracer.started[0] != "child" {
		t.Fatalf("expected child span start got %#v", tracer.started)
	}

	extracted, err := Extract(tracer, header)
	if err != nil {
		t.Fatal(err)
	}
	if extracted != tracer.context {
		t.Fatal("expected tracer extract context")
	}
	if _, err := ExtractFromContext(ctx, header); err != nil {
		t.Fatal(err)
	}
	if tracer.extractCount != 2 {
		t.Fatalf("expected 2 extracts got %d", tracer.extractCount)
	}

	if err := Inject("svc", span, header); err != nil {
		t.Fatal(err)
	}
	if err := InjectFromContext(ctx, span, header); err != nil {
		t.Fatal(err)
	}
	if tracer.injectCount != 2 {
		t.Fatalf("expected 2 injects got %d", tracer.injectCount)
	}

	tracer.extractErr = errors.New("extract failed")
	if _, err := Extract(tracer, header); err == nil {
		t.Fatal("expected extract error")
	}
	tracer.injectErr = errors.New("inject failed")
	if err := Inject("svc", span, header); err == nil {
		t.Fatal("expected inject error")
	}
}

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:encoding_safety:nominal
// SW-REQ-165:determinism:nominal
func TestRootAndHandle(t *testing.T) {
	resetTraceGlobals(t)

	tracer := &recordingTracer{name: "svc", extractErr: errors.New("no inbound span")}
	services.Store("svc", tracer)

	req := httptest.NewRequest(http.MethodPost, "/widgets?id=1", strings.NewReader("body"))
	req.ContentLength = 4
	span, rootedReq := Root("svc", req)
	if span == nil {
		t.Fatal("expected root span")
	}
	if got := GetServiceID(rootedReq.Context()); got != "svc" {
		t.Fatalf("expected service id svc got %q", got)
	}

	called := false
	handler := Handle("svc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := GetServiceID(r.Context()); got != "svc" {
			t.Fatalf("expected service id in handled request got %q", got)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected wrapped handler call")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status %d got %d", http.StatusAccepted, rec.Code)
	}
}

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:encoding_safety:nominal
// SW-REQ-165:determinism:nominal
func TestLogHelpers(t *testing.T) {
	span := &recordingSpan{tags: map[string]interface{}{}}
	ctx := opentracing.ContextWithSpan(context.Background(), span)
	logger := &recordingLogrus{}

	Debug(ctx, logger, "debug", 1)
	Error(ctx, logger, "error", 2)
	Warning(ctx, logger, "warn", 3)
	Info(ctx, logger, "info", 4)
	Log(context.Background(), opentracinglog.String("ignored", "without span"))

	wantLogs := []string{"debug:debug1", "error:error2", "warning:warn3", "info:info4"}
	if !reflect.DeepEqual(wantLogs, logger.entries) {
		t.Fatalf("expected %#v got %#v", wantLogs, logger.entries)
	}
	if len(span.fields) != 4 {
		t.Fatalf("expected 4 span log entries got %d", len(span.fields))
	}
}

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:determinism:nominal
func TestStdLogger(t *testing.T) {
	var out bytes.Buffer
	oldOutput := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&out)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
	})

	logger := StdLogger{}
	logger.Errorf("failed %s", "one")
	logger.Infof("started %s", "two")
	logger.Error("failed", "three")
	logger.Info("started", "four")

	got := out.String()
	for _, want := range []string{
		"[ERROR] trace:  failed one",
		"[INFO] trace:  started two",
		"[ERROR] trace:  failedthree",
		"[INFO] trace:  startedfour",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected log output to contain %q, got %q", want, got)
		}
	}
}

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:error_handling:nominal
// SW-REQ-165:error_handling:negative
// SW-REQ-165:determinism:nominal
func TestInit(t *testing.T) {
	tests := []struct {
		name       string
		tracerName string
		opts       map[string]interface{}
		wantName   string
		wantErr    string
	}{
		{
			name:       "returns noop tracer when no provider matches",
			tracerName: "noop",
			wantName:   "NoopTracer",
		},
		{
			name:       "selects zipkin provider and returns local init errors",
			tracerName: openzipkin.Name,
			wantErr:    "missing url",
		},
		{
			name:       "selects jaeger provider",
			tracerName: jaeger.Name,
			opts: map[string]interface{}{
				"disabled": true,
			},
			wantName: jaeger.Name,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Init(tt.tracerName, "svc", tt.opts, &recordingManagerLogger{})
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer got.Close()
			if got.Name() != tt.wantName {
				t.Fatalf("expected %q got %q", tt.wantName, got.Name())
			}
		})
	}
}

// Verifies: STK-REQ-090, SYS-REQ-178, SW-REQ-165
// MCDC SYS-REQ-178: trace_manager_operation_terminal=T => TRUE
// MCDC SW-REQ-165: trace_manager_operation_terminal=T => TRUE
// STK-REQ-090:STK-REQ-090-AC-01:acceptance
// STK-REQ-090:error_handling:negative
// SW-REQ-165:nominal:nominal
// SW-REQ-165:boundary:nominal
// SW-REQ-165:encoding_safety:nominal
// SW-REQ-165:error_handling:nominal
// SW-REQ-165:error_handling:negative
// SW-REQ-165:determinism:nominal
func TestTraceManagerReqProof(t *testing.T) {
	resetTraceGlobals(t)

	t.Run("service id context helpers", func(t *testing.T) {
		if got := GetServiceID(context.Background()); got != "" {
			t.Fatalf("unset service id = %q, want empty", got)
		}
		ctx := SetServiceID(context.Background(), "svc")
		if got := GetServiceID(ctx); got != "svc" {
			t.Fatalf("service id = %q, want svc", got)
		}
	})

	t.Run("manager state registration and no-op fallback", func(t *testing.T) {
		if IsEnabled() {
			t.Fatal("expected tracing disabled before setup")
		}
		if _, ok := Get("missing").(NoopTracer); !ok {
			t.Fatal("expected no-op tracer for missing service")
		}
		if err := AddTracer("", "svc"); !errors.Is(err, ErrManagerDisabled) {
			t.Fatalf("AddTracer disabled error = %v, want ErrManagerDisabled", err)
		}

		tracer := &recordingTracer{name: "configured"}
		var calls int
		SetInit(func(name string, service string, opts map[string]interface{}, logger Logger) (Tracer, error) {
			calls++
			if name != "configured" || service != "svc" || opts["sample"] != "value" {
				t.Fatalf("initializer args = name:%q service:%q opts:%#v", name, service, opts)
			}
			if _, ok := logger.(StdLogger); !ok {
				t.Fatalf("initializer logger = %T, want StdLogger", logger)
			}
			return tracer, nil
		})
		SetupTracing("configured", map[string]interface{}{"sample": "value"})
		if !IsEnabled() {
			t.Fatal("expected tracing enabled after setup")
		}
		if err := AddTracer("", "svc"); err != nil {
			t.Fatal(err)
		}
		if err := AddTracer("", "svc"); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatalf("initializer calls = %d, want 1", calls)
		}
		if got := Get("svc"); got != tracer {
			t.Fatal("expected registered tracer")
		}
	})

	tracer := &recordingTracer{name: "svc"}
	services.Store("svc", tracer)
	ctx := SetServiceID(context.Background(), "svc")
	header := http.Header{"B3": {"trace-span"}}

	t.Run("span extraction and injection helpers", func(t *testing.T) {
		span, spanCtx := Span(ctx, "child")
		if span == nil {
			t.Fatal("expected span")
		}
		if got := GetServiceID(spanCtx); got != "svc" {
			t.Fatalf("span context service id = %q, want svc", got)
		}
		if got := tracer.started[len(tracer.started)-1]; got != "child" {
			t.Fatalf("last started span = %q, want child", got)
		}

		extracted, err := Extract(tracer, header)
		if err != nil {
			t.Fatal(err)
		}
		if extracted != tracer.context {
			t.Fatal("expected extracted tracer context")
		}
		if _, err := ExtractFromContext(ctx, header); err != nil {
			t.Fatal(err)
		}
		if err := Inject("svc", span, header); err != nil {
			t.Fatal(err)
		}
		if err := InjectFromContext(ctx, span, header); err != nil {
			t.Fatal(err)
		}
		if tracer.extractCount != 2 || tracer.injectCount != 2 {
			t.Fatalf("extract/inject counts = %d/%d, want 2/2", tracer.extractCount, tracer.injectCount)
		}

		tracer.extractErr = errors.New("extract failed")
		if _, err := Extract(tracer, header); err == nil {
			t.Fatal("expected extract error")
		}
		tracer.extractErr = nil
		tracer.injectErr = errors.New("inject failed")
		if err := Inject("svc", span, header); err == nil {
			t.Fatal("expected inject error")
		}
		tracer.injectErr = nil
	})

	t.Run("handler root span setup", func(t *testing.T) {
		tracer.extractErr = errors.New("no inbound span")
		req := httptest.NewRequest(http.MethodPost, "/widgets?id=1", strings.NewReader("body"))
		req.ContentLength = 4
		span, rootedReq := Root("svc", req)
		if span == nil {
			t.Fatal("expected root span")
		}
		if got := GetServiceID(rootedReq.Context()); got != "svc" {
			t.Fatalf("rooted service id = %q, want svc", got)
		}

		called := false
		handler := Handle("svc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			if got := GetServiceID(r.Context()); got != "svc" {
				t.Fatalf("handled service id = %q, want svc", got)
			}
			w.WriteHeader(http.StatusAccepted)
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if !called {
			t.Fatal("expected wrapped handler call")
		}
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
		}
		tracer.extractErr = nil
	})

	t.Run("log helpers forward to logger and active span", func(t *testing.T) {
		span := &recordingSpan{tags: map[string]interface{}{}}
		logCtx := opentracing.ContextWithSpan(context.Background(), span)
		logger := &recordingLogrus{}

		Debug(logCtx, logger, "debug", 1)
		Error(logCtx, logger, "error", 2)
		Warning(logCtx, logger, "warn", 3)
		Info(logCtx, logger, "info", 4)
		Log(context.Background(), opentracinglog.String("ignored", "without span"))

		wantLogs := []string{"debug:debug1", "error:error2", "warning:warn3", "info:info4"}
		if !reflect.DeepEqual(wantLogs, logger.entries) {
			t.Fatalf("logger entries = %#v, want %#v", logger.entries, wantLogs)
		}
		if len(span.fields) != 4 {
			t.Fatalf("span log entries = %d, want 4", len(span.fields))
		}
	})

	t.Run("supported provider selection", func(t *testing.T) {
		tests := []struct {
			name       string
			tracerName string
			opts       map[string]interface{}
			wantName   string
			wantErr    string
		}{
			{name: "unknown provider returns noop", tracerName: "noop", wantName: "NoopTracer"},
			{name: "zipkin provider returns local init errors", tracerName: openzipkin.Name, wantErr: "missing url"},
			{name: "jaeger provider initializes disabled tracer", tracerName: jaeger.Name, opts: map[string]interface{}{"disabled": true}, wantName: jaeger.Name},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := Init(tt.tracerName, "svc", tt.opts, &recordingManagerLogger{})
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer got.Close()
				if got.Name() != tt.wantName {
					t.Fatalf("provider name = %q, want %q", got.Name(), tt.wantName)
				}
			})
		}
	})

	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if IsEnabled() {
		t.Fatal("expected close to disable tracing")
	}
	if _, ok := Get("svc").(NoopTracer); !ok {
		t.Fatal("expected close to remove registered tracer")
	}
}

func resetTraceGlobals(t *testing.T) {
	t.Helper()

	manager = &sync.Map{}
	services = &sync.Map{}
	enabled = atomic.Value{}
	logger = StdLogger{}
	initializer = Init

	t.Cleanup(func() {
		manager = &sync.Map{}
		services = &sync.Map{}
		enabled = atomic.Value{}
		logger = StdLogger{}
		initializer = Init
	})
}

type recordingTracer struct {
	opentracing.NoopTracer
	name         string
	closeErr     error
	extractErr   error
	injectErr    error
	closeCount   int
	extractCount int
	injectCount  int
	started      []string
	context      opentracing.SpanContext
}

func (t *recordingTracer) Name() string {
	return t.name
}

func (t *recordingTracer) Close() error {
	t.closeCount++
	return t.closeErr
}

func (t *recordingTracer) StartSpan(operationName string, opts ...opentracing.StartSpanOption) opentracing.Span {
	t.started = append(t.started, operationName)
	return &recordingSpan{tracer: t, tags: map[string]interface{}{}}
}

func (t *recordingTracer) Extract(format interface{}, carrier interface{}) (opentracing.SpanContext, error) {
	t.extractCount++
	if t.extractErr != nil {
		return nil, t.extractErr
	}
	if t.context == nil {
		t.context = &recordingSpanContext{}
	}
	return t.context, nil
}

func (t *recordingTracer) Inject(ctx opentracing.SpanContext, format interface{}, carrier interface{}) error {
	t.injectCount++
	return t.injectErr
}

type recordingSpanContext struct{}

func (*recordingSpanContext) ForeachBaggageItem(func(k, v string) bool) {}

type recordingSpan struct {
	tracer      opentracing.Tracer
	fields      [][]opentracinglog.Field
	tags        map[string]interface{}
	finishCount int
}

func (s *recordingSpan) Finish() {
	s.finishCount++
}

func (s *recordingSpan) FinishWithOptions(opentracing.FinishOptions) {
	s.finishCount++
}

func (s *recordingSpan) Context() opentracing.SpanContext {
	return &recordingSpanContext{}
}

func (s *recordingSpan) SetOperationName(operationName string) opentracing.Span {
	return s
}

func (s *recordingSpan) SetTag(key string, value interface{}) opentracing.Span {
	s.tags[key] = value
	return s
}

func (s *recordingSpan) LogFields(fields ...opentracinglog.Field) {
	s.fields = append(s.fields, fields)
}

func (s *recordingSpan) LogKV(alternatingKeyValues ...interface{}) {}

func (s *recordingSpan) SetBaggageItem(restrictedKey, value string) opentracing.Span {
	return s
}

func (s *recordingSpan) BaggageItem(restrictedKey string) string {
	return ""
}

func (s *recordingSpan) Tracer() opentracing.Tracer {
	if s.tracer != nil {
		return s.tracer
	}
	return opentracing.NoopTracer{}
}

func (s *recordingSpan) LogEvent(event string) {}

func (s *recordingSpan) LogEventWithPayload(event string, payload interface{}) {}

func (s *recordingSpan) Log(data opentracing.LogData) {}

type recordingLogrus struct {
	entries []string
}

func (l *recordingLogrus) Debug(args ...interface{}) {
	l.entries = append(l.entries, "debug:"+fmt.Sprint(args...))
}

func (l *recordingLogrus) Error(args ...interface{}) {
	l.entries = append(l.entries, "error:"+fmt.Sprint(args...))
}

func (l *recordingLogrus) Warning(args ...interface{}) {
	l.entries = append(l.entries, "warning:"+fmt.Sprint(args...))
}

func (l *recordingLogrus) Info(args ...interface{}) {
	l.entries = append(l.entries, "info:"+fmt.Sprint(args...))
}

type recordingManagerLogger struct {
	errors []string
	infos  []string
}

func (l *recordingManagerLogger) Errorf(format string, args ...interface{}) {
	l.errors = append(l.errors, fmt.Sprintf(format, args...))
}

func (l *recordingManagerLogger) Info(args ...interface{}) {
	l.infos = append(l.infos, fmt.Sprint(args...))
}

func (l *recordingManagerLogger) Infof(format string, args ...interface{}) {
	l.infos = append(l.infos, fmt.Sprintf(format, args...))
}

var _ opentracing.Span = (*recordingSpan)(nil)
var _ opentracing.SpanContext = (*recordingSpanContext)(nil)
var _ Tracer = (*recordingTracer)(nil)
