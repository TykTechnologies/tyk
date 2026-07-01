package jaeger

import (
	"fmt"
	"reflect"
	"testing"

	jaeger "github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"

	tykconf "github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-086, SYS-REQ-174, SW-REQ-161
// STK-REQ-086:STK-REQ-086-AC-01:acceptance
// SW-REQ-161:nominal:nominal
// SW-REQ-161:boundary:nominal
// SW-REQ-161:determinism:nominal
func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		options func(t *testing.T) map[string]interface{}
		want    config.Configuration
	}{
		{
			name: "loads json compatible jaeger options",
			options: func(t *testing.T) map[string]interface{} {
				var c tykconf.Config
				if err := tykconf.Load([]string{"testdata/jaeger.json"}, &c); err != nil {
					t.Fatal(err)
				}
				return c.Tracer.Options
			},
			want: config.Configuration{
				ServiceName: "tyk-gateway",
				Sampler: &config.SamplerConfig{
					Type:    jaeger.SamplerTypeConst,
					Param:   1,
					Options: []jaeger.SamplerOption{},
				},
				Reporter: &config.ReporterConfig{
					LogSpans:           true,
					LocalAgentHostPort: "jaeger:6831",
					HTTPHeaders: map[string]string{
						"test": "1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadedConfig, err := Load(tt.options(t))
			if err != nil {
				t.Fatal(err)
			}

			fields := []struct {
				field  string
				expect interface{}
				got    interface{}
			}{
				{"serviceName", tt.want.ServiceName, loadedConfig.ServiceName},
				{"rpc_metrics", tt.want.RPCMetrics, loadedConfig.RPCMetrics},
				{"sampler", tt.want.Sampler, loadedConfig.Sampler},
				{"reporter", tt.want.Reporter, loadedConfig.Reporter},
			}
			for _, v := range fields {
				if !reflect.DeepEqual(v.expect, v.got) {
					t.Errorf("%v: expected %#v got %#v", v.field, v.expect, v.got)
				}
			}
		})
	}
}

// Verifies: STK-REQ-086, SYS-REQ-174, SW-REQ-161
// SW-REQ-161:nominal:nominal
// SW-REQ-161:boundary:nominal
// SW-REQ-161:determinism:nominal
func TestTraceName(t *testing.T) {
	trace := Trace{}
	if got := trace.Name(); got != Name {
		t.Fatalf("expected %q got %q", Name, got)
	}
}

// Verifies: STK-REQ-086, SYS-REQ-174, SW-REQ-161
// SW-REQ-161:nominal:nominal
// SW-REQ-161:boundary:nominal
// SW-REQ-161:determinism:nominal
func TestWrapLoggerError(t *testing.T) {
	logger := &recordingLogger{}
	wrapLogger{Logger: logger}.Error("jaeger error")

	if want, got := "jaeger error", logger.errors[0]; got != want {
		t.Fatalf("expected %q got %q", want, got)
	}
}

// Verifies: STK-REQ-086, SYS-REQ-174, SW-REQ-161
// SW-REQ-161:nominal:nominal
// SW-REQ-161:boundary:nominal
// SW-REQ-161:determinism:nominal
func TestInit(t *testing.T) {
	trace, err := Init("override-service", map[string]interface{}{
		"disabled": true,
		"sampler": map[string]interface{}{
			"type":  jaeger.SamplerTypeConst,
			"param": 1,
		},
	}, &recordingLogger{})
	if err != nil {
		t.Fatal(err)
	}
	defer trace.Close()

	if trace.Tracer == nil {
		t.Fatal("expected tracer")
	}
	if trace.Closer == nil {
		t.Fatal("expected closer")
	}
	if got := trace.Name(); got != Name {
		t.Fatalf("expected %q got %q", Name, got)
	}
}

// Verifies: STK-REQ-086, SYS-REQ-174, SW-REQ-161
// MCDC SYS-REQ-174: jaeger_trace_adapter_operation_terminal=T => TRUE
// MCDC SW-REQ-161: jaeger_trace_adapter_operation_terminal=T => TRUE
// STK-REQ-086:STK-REQ-086-AC-01:acceptance
// SW-REQ-161:nominal:nominal
// SW-REQ-161:boundary:nominal
// SW-REQ-161:determinism:nominal
func TestJaegerTraceAdapterReqProof(t *testing.T) {
	loadedConfig, err := Load(map[string]interface{}{
		"serviceName": "tyk-gateway",
		"sampler": map[string]interface{}{
			"type":  jaeger.SamplerTypeConst,
			"param": 1,
		},
		"reporter": map[string]interface{}{
			"logSpans": true,
			"http_headers": map[string]interface{}{
				"test": "1",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if loadedConfig.ServiceName != "tyk-gateway" {
		t.Fatalf("ServiceName = %q, want tyk-gateway", loadedConfig.ServiceName)
	}
	if loadedConfig.Sampler == nil || loadedConfig.Sampler.Type != jaeger.SamplerTypeConst || loadedConfig.Sampler.Param != 1 {
		t.Fatalf("Sampler = %#v, want const sampler with param 1", loadedConfig.Sampler)
	}
	if loadedConfig.Reporter == nil || loadedConfig.Reporter.HTTPHeaders["test"] != "1" {
		t.Fatalf("Reporter = %#v, want HTTP header test=1", loadedConfig.Reporter)
	}

	logger := &recordingLogger{}
	wrapLogger{Logger: logger}.Error("jaeger error")
	if len(logger.errors) != 1 || logger.errors[0] != "jaeger error" {
		t.Fatalf("logger errors = %#v, want jaeger error", logger.errors)
	}

	trace, err := Init("override-service", map[string]interface{}{
		"disabled": true,
		"sampler": map[string]interface{}{
			"type":  jaeger.SamplerTypeConst,
			"param": 1,
		},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer trace.Close()

	if trace.Tracer == nil {
		t.Fatal("expected tracer")
	}
	if trace.Closer == nil {
		t.Fatal("expected closer")
	}
	if got := trace.Name(); got != Name {
		t.Fatalf("Name = %q, want %q", got, Name)
	}
}

// Reproduces: KI-JAEGER-LOAD-UNSUPPORTED-OPTION-PANIC
// Verifies: SYS-REQ-174
func TestKnownIssue_LoadPanicsOnUnsupportedOptionValue(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected panic for unsupported option value")
		}
	}()

	_, _ = Load(map[string]interface{}{
		"serviceName": func() {},
	})
}

type recordingLogger struct {
	errors []string
	infos  []string
}

func (l *recordingLogger) Errorf(msg string, args ...interface{}) {
	l.errors = append(l.errors, fmt.Sprintf(msg, args...))
}

func (l *recordingLogger) Infof(msg string, args ...interface{}) {
	l.infos = append(l.infos, fmt.Sprintf(msg, args...))
}
