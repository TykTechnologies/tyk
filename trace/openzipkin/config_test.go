package openzipkin

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	opentracinglog "github.com/opentracing/opentracing-go/log"
	zipkin "github.com/openzipkin/zipkin-go"
	"github.com/openzipkin/zipkin-go/model"
	"github.com/openzipkin/zipkin-go/reporter"

	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// STK-REQ-089:STK-REQ-089-AC-01:acceptance
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:error_handling:negative
// SW-REQ-164:determinism:nominal
func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		options func(t *testing.T) map[string]interface{}
		want    config.ZipkinConfig
		wantErr bool
	}{
		{
			name: "loads json compatible zipkin options",
			options: func(t *testing.T) map[string]interface{} {
				var c config.Config
				if err := config.Load([]string{"testdata/zipkin.json"}, &c); err != nil {
					t.Fatal(err)
				}
				return c.Tracer.Options
			},
			want: config.ZipkinConfig{
				Reporter: config.Reporter{
					URL: "http:localhost:9411/api/v2/spans",
				},
			},
		},
		{
			name: "returns errors for json incompatible options",
			options: func(t *testing.T) map[string]interface{} {
				return map[string]interface{}{"unsupported": func() {}}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(tt.options(t))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tt.want, *got) {
				t.Fatalf("expected %#v got %#v", tt.want, *got)
			}
		})
	}
}

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:error_handling:nominal
// SW-REQ-164:error_handling:negative
// SW-REQ-164:determinism:nominal
func TestGetSampler(t *testing.T) {
	tests := []struct {
		name      string
		sampler   config.Sampler
		wantErr   bool
		decisions map[uint64]bool
	}{
		{
			name:      "default sampler always samples",
			decisions: map[uint64]bool{1: true, 2: true},
		},
		{
			name: "boundary sampler accepts full sampling rate",
			sampler: config.Sampler{
				Name: "boundary",
				Rate: 1,
				Salt: 23,
			},
			decisions: map[uint64]bool{1: true, 2: true},
		},
		{
			name: "count sampler accepts full sampling rate",
			sampler: config.Sampler{
				Name: "count",
				Rate: 1,
			},
			decisions: map[uint64]bool{1: true, 2: true},
		},
		{
			name: "mod sampler applies deterministic modulus",
			sampler: config.Sampler{
				Name: "mod",
				Mod:  2,
			},
			decisions: map[uint64]bool{2: true, 3: false},
		},
		{
			name: "boundary sampler returns dependency validation errors",
			sampler: config.Sampler{
				Name: "boundary",
				Rate: 2,
			},
			wantErr: true,
		},
		{
			name: "count sampler returns dependency validation errors",
			sampler: config.Sampler{
				Name: "count",
				Rate: 2,
			},
			wantErr: true,
		},
		{
			name: "unknown sampler name returns error",
			sampler: config.Sampler{
				Name: "unknown",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sampler, err := getSampler(tt.sampler)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for id, want := range tt.decisions {
				if got := sampler(id); got != want {
					t.Fatalf("id %d: expected %v got %v", id, want, got)
				}
			}
		})
	}
}

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:error_handling:nominal
// SW-REQ-164:error_handling:negative
// SW-REQ-164:determinism:nominal
// STK-REQ-089:error_handling:negative
func TestInitAndName(t *testing.T) {
	tests := []struct {
		name    string
		opts    map[string]interface{}
		wantErr string
	}{
		{
			name: "initializes local tracer with reporter url and default sampler",
			opts: map[string]interface{}{
				"reporter": map[string]interface{}{
					"url": "http://127.0.0.1:9411/api/v2/spans",
				},
			},
		},
		{
			name:    "returns error when reporter url is missing",
			opts:    map[string]interface{}{},
			wantErr: "missing url",
		},
		{
			name: "returns sampler errors",
			opts: map[string]interface{}{
				"reporter": map[string]interface{}{
					"url": "http://127.0.0.1:9411/api/v2/spans",
				},
				"sampler": map[string]interface{}{
					"name": "unknown",
				},
			},
			wantErr: "unknown sampler",
		},
		{
			name: "returns option decoding errors",
			opts: map[string]interface{}{
				"unsupported": func() {},
			},
			wantErr: "unsupported type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer, err := Init("tyk-gateway", tt.opts)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q got %q", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer tracer.Close()

			if tracer.Tracer == nil {
				t.Fatal("expected tracer")
			}
			if tracer.Reporter == nil {
				t.Fatal("expected reporter")
			}
			if got := tracer.Name(); got != Name {
				t.Fatalf("expected %q got %q", Name, got)
			}
		})
	}
}

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:encoding_safety:nominal
// SW-REQ-164:error_handling:nominal
// SW-REQ-164:error_handling:negative
// SW-REQ-164:determinism:nominal
func TestHTTPHeaderExtractionAndInjection(t *testing.T) {
	tests := []struct {
		name        string
		carrier     interface{}
		wantTraceID string
		wantSpanID  string
		wantErr     error
		wantErrText string
	}{
		{
			name: "extracts multi header b3 carrier",
			carrier: opentracing.HTTPHeadersCarrier(http.Header{
				"X-B3-Traceid": {"0000000000000001"},
				"X-B3-Spanid":  {"0000000000000002"},
				"X-B3-Sampled": {"1"},
			}),
			wantTraceID: "0000000000000001",
			wantSpanID:  "0000000000000002",
		},
		{
			name: "extracts single header b3 carrier",
			carrier: opentracing.HTTPHeadersCarrier(http.Header{
				"B3": {"0000000000000003-0000000000000004-1"},
			}),
			wantTraceID: "0000000000000003",
			wantSpanID:  "0000000000000004",
		},
		{
			name:    "rejects unsupported carrier",
			carrier: map[string]string{},
			wantErr: opentracing.ErrInvalidCarrier,
		},
		{
			name: "returns parse errors",
			carrier: opentracing.HTTPHeadersCarrier(http.Header{
				"B3": {"invalid"},
			}),
			wantErrText: "invalid B3 TraceID value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := extractorFn(extractHTTPHeader).extract(tt.carrier)
			if tt.wantErr != nil || tt.wantErrText != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) && !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Fatalf("expected %v got %v", tt.wantErr, err)
				}
				if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("expected error containing %q got %v", tt.wantErrText, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := ctx.TraceID.String(); got != tt.wantTraceID {
				t.Fatalf("expected trace id %q got %q", tt.wantTraceID, got)
			}
			if got := ctx.ID.String(); got != tt.wantSpanID {
				t.Fatalf("expected span id %q got %q", tt.wantSpanID, got)
			}

			header := opentracing.HTTPHeadersCarrier(http.Header{})
			if err := injectorFn(injectHTTPHeaders).inject(ctx, header); err != nil {
				t.Fatal(err)
			}
			if got := http.Header(header).Get("b3"); got == "" {
				t.Fatal("expected injected b3 header")
			}
		})
	}

	if err := injectHTTPHeaders(emptyContext, opentracing.HTTPHeadersCarrier(http.Header{})); err != nil {
		t.Fatal(err)
	}
	if err := injectHTTPHeaders(spanContext{}, map[string]string{}); !errors.Is(err, opentracing.ErrInvalidCarrier) {
		t.Fatalf("expected invalid carrier got %v", err)
	}
}

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:encoding_safety:nominal
// SW-REQ-164:error_handling:nominal
// SW-REQ-164:error_handling:negative
// SW-REQ-164:determinism:nominal
func TestZipkinTracerExtractInjectAndStartSpan(t *testing.T) {
	zipTracer, err := zipkin.NewTracer(reporter.NewNoopReporter())
	if err != nil {
		t.Fatal(err)
	}
	tracer := NewTracer(zipTracer)

	parent, err := tracer.Extract(opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(http.Header{
		"B3": {"0000000000000011-0000000000000022-1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tracer.Extract(opentracing.TextMap, opentracing.HTTPHeadersCarrier(http.Header{})); !errors.Is(err, opentracing.ErrUnsupportedFormat) {
		t.Fatalf("expected unsupported format got %v", err)
	}

	header := opentracing.HTTPHeadersCarrier(http.Header{})
	if err := tracer.Inject(parent, opentracing.HTTPHeaders, header); err != nil {
		t.Fatal(err)
	}
	if got := http.Header(header).Get("b3"); got == "" {
		t.Fatal("expected injected b3 header")
	}
	if err := tracer.Inject(foreignSpanContext{}, opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(http.Header{})); !errors.Is(err, opentracing.ErrInvalidSpanContext) {
		t.Fatalf("expected invalid span context got %v", err)
	}
	if err := tracer.Inject(parent, opentracing.TextMap, opentracing.HTTPHeadersCarrier(http.Header{})); !errors.Is(err, opentracing.ErrUnsupportedFormat) {
		t.Fatalf("expected unsupported format got %v", err)
	}

	root := tracer.StartSpan("root", opentracing.Tag{Key: "status", Value: 200})
	if root == nil {
		t.Fatal("expected root span")
	}
	defer root.Finish()

	child := tracer.StartSpan("child", opentracing.ChildOf(parent))
	if child == nil {
		t.Fatal("expected child span")
	}
	defer child.Finish()
}

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:encoding_safety:nominal
// SW-REQ-164:determinism:nominal
func TestSpanFacadeForwardsLocalOperations(t *testing.T) {
	sampled := true
	fake := &recordingZipkinSpan{
		ctx: model.SpanContext{
			TraceID: model.TraceID{Low: 1},
			ID:      model.ID(2),
			Sampled: &sampled,
		},
		tags: map[string]string{},
	}
	tracer := &zipkinTracer{}
	span := Span{span: fake, tr: tracer}

	if got := span.Context().(spanContext).ID.String(); got != "0000000000000002" {
		t.Fatalf("expected span context id got %q", got)
	}
	if span.Tracer() != tracer {
		t.Fatal("expected owning tracer")
	}
	if returned := span.SetOperationName("updated"); returned == nil {
		t.Fatal("expected returned span")
	}
	if got := fake.name; got != "updated" {
		t.Fatalf("expected operation name %q got %q", "updated", got)
	}
	span.SetTag("code", 200)
	if got := fake.tags["code"]; got != "200" {
		t.Fatalf("expected stringified tag got %q", got)
	}
	span.LogFields(
		opentracinglog.String("event", "selected"),
		opentracinglog.Int("count", 2),
	)
	if len(fake.annotations) != 2 {
		t.Fatalf("expected 2 annotations got %d", len(fake.annotations))
	}
	span.Finish()
	span.FinishWithOptions(opentracing.FinishOptions{})
	if got := fake.finishCount; got != 2 {
		t.Fatalf("expected 2 finishes got %d", got)
	}
	if got := span.SetBaggageItem("key", "value"); got == nil {
		t.Fatal("expected baggage setter to return span")
	}
	if got := span.BaggageItem("key"); got != "" {
		t.Fatalf("expected empty baggage item got %q", got)
	}

	span.LogKV("key", "value")
	span.LogEvent("event")
	span.LogEventWithPayload("event", "payload")
	span.Log(opentracing.LogData{Event: "event"})
	spanContext{}.ForeachBaggageItem(func(k, v string) bool {
		t.Fatal("expected no baggage callback")
		return false
	})
}

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:encoding_safety:nominal
// SW-REQ-164:determinism:nominal
func TestLogEncoderEmitsSupportedFieldTypes(t *testing.T) {
	var got []string
	encoder := &logEncoder{h: func(key string, value interface{}) {
		got = append(got, fmt.Sprintf("%s=%v", key, value))
	}}

	encoder.EmitString("string", "value")
	encoder.EmitBool("bool", true)
	encoder.EmitInt("int", 1)
	encoder.EmitInt32("int32", 2)
	encoder.EmitInt64("int64", 3)
	encoder.EmitUint32("uint32", 4)
	encoder.EmitUint64("uint64", 5)
	encoder.EmitFloat32("float32", 6.5)
	encoder.EmitFloat64("float64", 7.5)
	encoder.EmitObject("object", "value")
	encoder.EmitLazyLogger(nil)

	want := []string{
		"string=value",
		"bool=true",
		"int=1",
		"int32=2",
		"int64=3",
		"uint32=4",
		"uint64=5",
		"float32=6.5",
		"float64=7.5",
		"object=value",
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("expected %#v got %#v", want, got)
	}

	(&logEncoder{}).EmitString("ignored", "value")
}

// Verifies: STK-REQ-089, SYS-REQ-177, SW-REQ-164
// MCDC SYS-REQ-177: openzipkin_trace_adapter_operation_terminal=T => TRUE
// MCDC SW-REQ-164: openzipkin_trace_adapter_operation_terminal=T => TRUE
// STK-REQ-089:STK-REQ-089-AC-01:acceptance
// STK-REQ-089:error_handling:negative
// SW-REQ-164:nominal:nominal
// SW-REQ-164:boundary:nominal
// SW-REQ-164:encoding_safety:nominal
// SW-REQ-164:error_handling:nominal
// SW-REQ-164:error_handling:negative
// SW-REQ-164:determinism:nominal
func TestOpenZipkinTraceAdapterReqProof(t *testing.T) {
	t.Run("decodes json compatible zipkin options", func(t *testing.T) {
		var c config.Config
		if err := config.Load([]string{"testdata/zipkin.json"}, &c); err != nil {
			t.Fatal(err)
		}

		got, err := Load(c.Tracer.Options)
		if err != nil {
			t.Fatal(err)
		}
		if got.Reporter.URL != "http:localhost:9411/api/v2/spans" {
			t.Fatalf("Reporter.URL = %q, want configured URL", got.Reporter.URL)
		}
	})

	t.Run("selects supported samplers and rejects unsupported names", func(t *testing.T) {
		tests := []struct {
			name      string
			sampler   config.Sampler
			decisions map[uint64]bool
			wantErr   string
		}{
			{name: "default sampler", decisions: map[uint64]bool{1: true, 2: true}},
			{name: "boundary sampler", sampler: config.Sampler{Name: "boundary", Rate: 1, Salt: 23}, decisions: map[uint64]bool{1: true, 2: true}},
			{name: "count sampler", sampler: config.Sampler{Name: "count", Rate: 1}, decisions: map[uint64]bool{1: true, 2: true}},
			{name: "mod sampler", sampler: config.Sampler{Name: "mod", Mod: 2}, decisions: map[uint64]bool{2: true, 3: false}},
			{name: "unknown sampler", sampler: config.Sampler{Name: "unknown"}, wantErr: "unknown sampler"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				sampler, err := getSampler(tt.sampler)
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for id, want := range tt.decisions {
					if got := sampler(id); got != want {
						t.Fatalf("id %d: sampler = %v, want %v", id, got, want)
					}
				}
			})
		}
	})

	t.Run("initializes local tracer and returns local initialization errors", func(t *testing.T) {
		tracer, err := Init("tyk-gateway", map[string]interface{}{
			"reporter": map[string]interface{}{
				"url": "http://127.0.0.1:9411/api/v2/spans",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer tracer.Close()

		if tracer.Tracer == nil {
			t.Fatal("expected tracer")
		}
		if tracer.Reporter == nil {
			t.Fatal("expected reporter")
		}
		if got := tracer.Name(); got != Name {
			t.Fatalf("Name = %q, want %q", got, Name)
		}

		if _, err := Init("tyk-gateway", map[string]interface{}{}); err == nil || !strings.Contains(err.Error(), "missing url") {
			t.Fatalf("expected missing url error, got %v", err)
		}
		if _, err := Init("tyk-gateway", map[string]interface{}{
			"reporter": map[string]interface{}{
				"url": "http://127.0.0.1:9411/api/v2/spans",
			},
			"sampler": map[string]interface{}{
				"name": "unknown",
			},
		}); err == nil || !strings.Contains(err.Error(), "unknown sampler") {
			t.Fatalf("expected unknown sampler error, got %v", err)
		}
	})

	t.Run("converts supported b3 http header carriers", func(t *testing.T) {
		zipTracer, err := zipkin.NewTracer(reporter.NewNoopReporter())
		if err != nil {
			t.Fatal(err)
		}
		tracer := NewTracer(zipTracer)

		parent, err := tracer.Extract(opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(http.Header{
			"B3": {"0000000000000011-0000000000000022-1"},
		}))
		if err != nil {
			t.Fatal(err)
		}

		header := opentracing.HTTPHeadersCarrier(http.Header{})
		if err := tracer.Inject(parent, opentracing.HTTPHeaders, header); err != nil {
			t.Fatal(err)
		}
		if got := http.Header(header).Get("b3"); got == "" {
			t.Fatal("expected injected b3 header")
		}
		if _, err := tracer.Extract(opentracing.TextMap, opentracing.HTTPHeadersCarrier(http.Header{})); !errors.Is(err, opentracing.ErrUnsupportedFormat) {
			t.Fatalf("expected unsupported extract format, got %v", err)
		}
		if err := tracer.Inject(foreignSpanContext{}, opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(http.Header{})); !errors.Is(err, opentracing.ErrInvalidSpanContext) {
			t.Fatalf("expected invalid span context, got %v", err)
		}
		if err := tracer.Inject(parent, opentracing.TextMap, opentracing.HTTPHeadersCarrier(http.Header{})); !errors.Is(err, opentracing.ErrUnsupportedFormat) {
			t.Fatalf("expected unsupported inject format, got %v", err)
		}
	})

	t.Run("forwards local span facade operations", func(t *testing.T) {
		sampled := true
		fake := &recordingZipkinSpan{
			ctx: model.SpanContext{
				TraceID: model.TraceID{Low: 1},
				ID:      model.ID(2),
				Sampled: &sampled,
			},
			tags: map[string]string{},
		}
		tracer := &zipkinTracer{}
		span := Span{span: fake, tr: tracer}

		if got := span.Context().(spanContext).ID.String(); got != "0000000000000002" {
			t.Fatalf("span context id = %q, want 0000000000000002", got)
		}
		if span.Tracer() != tracer {
			t.Fatal("expected owning tracer")
		}
		span.SetOperationName("updated")
		if fake.name != "updated" {
			t.Fatalf("span name = %q, want updated", fake.name)
		}
		span.SetTag("code", 200)
		if got := fake.tags["code"]; got != "200" {
			t.Fatalf("tag code = %q, want 200", got)
		}
		span.LogFields(opentracinglog.String("event", "selected"), opentracinglog.Int("count", 2))
		if len(fake.annotations) != 2 {
			t.Fatalf("annotations length = %d, want 2", len(fake.annotations))
		}
		span.Finish()
		span.FinishWithOptions(opentracing.FinishOptions{})
		if fake.finishCount != 2 {
			t.Fatalf("finish count = %d, want 2", fake.finishCount)
		}
	})
}

type foreignSpanContext struct{}

func (foreignSpanContext) ForeachBaggageItem(func(k, v string) bool) {}

type recordingZipkinSpan struct {
	ctx         model.SpanContext
	name        string
	tags        map[string]string
	annotations []string
	finishCount int
	flushCount  int
}

func (s *recordingZipkinSpan) Context() model.SpanContext {
	return s.ctx
}

func (s *recordingZipkinSpan) SetName(name string) {
	s.name = name
}

func (s *recordingZipkinSpan) SetRemoteEndpoint(*model.Endpoint) {}

func (s *recordingZipkinSpan) Annotate(_ time.Time, value string) {
	s.annotations = append(s.annotations, value)
}

func (s *recordingZipkinSpan) Tag(key string, value string) {
	s.tags[key] = value
}

func (s *recordingZipkinSpan) Finish() {
	s.finishCount++
}

func (s *recordingZipkinSpan) FinishedWithDuration(time.Duration) {
	s.finishCount++
}

func (s *recordingZipkinSpan) Flush() {
	s.flushCount++
}
