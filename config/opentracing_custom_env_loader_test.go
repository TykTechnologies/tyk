package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	jaeger "github.com/uber/jaeger-client-go/config"
)

// Verifies: STK-REQ-033, SYS-REQ-121, SW-REQ-108
// SW-REQ-108:nominal:nominal
// SW-REQ-108:boundary:nominal
// MCDC SYS-REQ-121: opentracing_configuration_operation_requested=F, opentracing_configuration_result_determined=F => TRUE
// MCDC SYS-REQ-121: opentracing_configuration_operation_requested=T, opentracing_configuration_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-121: opentracing_configuration_operation_requested=T, opentracing_configuration_result_determined=F => FALSE -- violation row is the negation of the local opentracing configuration helper guarantee; these tests assert requested tracing configuration operations either skip unrelated tracer names, decode options, apply environment overrides, or return explicit local errors [category: defensive] [reviewed: agent:codex]
func TestLoadZipkin(t *testing.T) {
	base := ZipkinConfig{
		Reporter: Reporter{
			URL:        "http://example.com",
			BatchSize:  10,
			MaxBacklog: 20,
		},
		Sampler: Sampler{
			Name: "boundary",
			Rate: 10.1,
			Salt: 10,
			Mod:  12,
		},
	}
	sample := []struct {
		env   string
		value string
	}{
		{"TYK_GW_TRACER_OPTIONS_REPORTER_URL", base.Reporter.URL},
		{"TYK_GW_TRACER_OPTIONS_REPORTER_BATCHSIZE", fmt.Sprint(base.Reporter.BatchSize)},
		{"TYK_GW_TRACER_OPTIONS_REPORTER_MAXBACKLOG", fmt.Sprint(base.Reporter.MaxBacklog)},
		{"TYK_GW_TRACER_OPTIONS_SAMPLER_NAME", base.Sampler.Name},
		{"TYK_GW_TRACER_OPTIONS_SAMPLER_SALT", fmt.Sprint(base.Sampler.Salt)},
		{"TYK_GW_TRACER_OPTIONS_SAMPLER_MOD", fmt.Sprint(base.Sampler.Mod)},
	}

	t.Run("loads env vars", func(t *testing.T) {
		for _, v := range sample {
			err := os.Setenv(v.env, v.value)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer func() {
			for _, v := range sample {
				os.Unsetenv(v.env)
			}
		}()
		var conf Config
		err := Load([]string{"testdata/zipkin.json"}, &conf)
		if err != nil {
			t.Fatal(err)
		}
		var got ZipkinConfig
		err = DecodeJSON(&got, conf.Tracer.Options)
		if err != nil {
			t.Fatal(err)
		}
		if base.Reporter.URL != got.Reporter.URL {
			t.Errorf("expected %#v got %#v", base.Reporter.URL, got.Reporter.URL)
		}
		if base.Sampler.Name != got.Sampler.Name {
			t.Errorf("expected %#v got %#v", base.Sampler.Name, got.Sampler.Name)
		}
	})
}

// Verifies: STK-REQ-033, SYS-REQ-121, SW-REQ-108
// SW-REQ-108:nominal:nominal
// SW-REQ-108:boundary:nominal
func TestLoadJaeger(t *testing.T) {
	name := "jaeger-test-service"
	sample := []struct {
		env   string
		value string
	}{
		{"TYK_GW_TRACER_OPTIONS_SERVICENAME", name},
	}

	t.Run("Loads env vars", func(t *testing.T) {
		for _, v := range sample {
			err := os.Setenv(v.env, v.value)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer func() {
			for _, v := range sample {
				os.Unsetenv(v.env)
			}
		}()

		var conf Config
		err := Load([]string{"testdata/jaeger.json"}, &conf)
		if err != nil {
			t.Fatal(err)
		}
		var got jaeger.Configuration
		err = DecodeYAML(&got, conf.Tracer.Options)
		if err != nil {
			t.Fatal(err)
		}
		if got.ServiceName != name {
			t.Errorf("expected %#v got %#v", name, got.ServiceName)
		}
	})
}

// Verifies: STK-REQ-033, SYS-REQ-121, SW-REQ-108
// SW-REQ-108:nominal:nominal
// SW-REQ-108:boundary:nominal
// SW-REQ-108:error_handling:negative
func TestOpenTracingDecodeHelpers(t *testing.T) {
	t.Run("DecodeJSON converts map to typed zipkin config", func(t *testing.T) {
		var got ZipkinConfig
		err := DecodeJSON(&got, map[string]interface{}{
			"reporter": map[string]interface{}{
				"url":         "http://zipkin.example",
				"batch_size":  float64(10),
				"max_backlog": float64(20),
			},
			"sampler": map[string]interface{}{
				"name": "boundary",
				"rate": 10.1,
				"salt": float64(10),
				"mod":  float64(12),
			},
		})

		require.NoError(t, err)
		require.Equal(t, "http://zipkin.example", got.Reporter.URL)
		require.Equal(t, 10, got.Reporter.BatchSize)
		require.Equal(t, uint64(12), got.Sampler.Mod)
	})

	t.Run("DecodeJSON returns marshal errors", func(t *testing.T) {
		var got map[string]interface{}
		err := DecodeJSON(&got, map[string]interface{}{"unsupported": func() {}})

		require.Error(t, err)
	})

	t.Run("DecodeYAML converts map to typed jaeger config", func(t *testing.T) {
		var got jaeger.Configuration
		err := DecodeYAML(&got, map[string]interface{}{
			"serviceName": "jaeger-test-service",
			"disabled":    true,
		})

		require.NoError(t, err)
		require.Equal(t, "jaeger-test-service", got.ServiceName)
		require.True(t, got.Disabled)
	})

	t.Run("DecodeYAML returns unmarshal errors", func(t *testing.T) {
		var got int
		err := DecodeYAML(&got, map[string]interface{}{"serviceName": "jaeger-test-service"})

		require.Error(t, err)
	})
}

// Verifies: STK-REQ-033, SYS-REQ-121, SW-REQ-108
// SW-REQ-108:boundary:nominal
func TestOpenTracingLoadersSkipUnrelatedTracerNames(t *testing.T) {
	tests := []struct {
		name       string
		loader     func(string, *Config) error
		tracerName string
	}{
		{
			name:       "zipkin loader skips jaeger tracer",
			loader:     loadZipkin,
			tracerName: "jaeger",
		},
		{
			name:       "jaeger loader skips zipkin tracer",
			loader:     loadJaeger,
			tracerName: "zipkin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := map[string]interface{}{"preserve": "value"}
			conf := &Config{
				Tracer: Tracer{
					Name:    tt.tracerName,
					Options: options,
				},
			}

			require.NoError(t, tt.loader("TYK_GW", conf))
			require.Equal(t, options, conf.Tracer.Options)
		})
	}
}

// Verifies: STK-REQ-033, SYS-REQ-121, SW-REQ-108
// STK-REQ-033:error_handling:negative
// SW-REQ-108:error_handling:negative
func TestOpenTracingLoadersReturnEnvDecodeErrors(t *testing.T) {
	tests := []struct {
		name   string
		env    string
		value  string
		conf   Config
		loader func(string, *Config) error
	}{
		{
			name:  "zipkin invalid batch size",
			env:   "TYK_GW_TRACER_OPTIONS_REPORTER_BATCHSIZE",
			value: "not-an-int",
			conf: Config{
				Tracer: Tracer{
					Name:    "zipkin",
					Options: map[string]interface{}{},
				},
			},
			loader: loadZipkin,
		},
		{
			name:  "jaeger invalid disabled flag",
			env:   "TYK_GW_TRACER_OPTIONS_DISABLED",
			value: "not-a-bool",
			conf: Config{
				Tracer: Tracer{
					Name:    "jaeger",
					Options: map[string]interface{}{},
				},
			},
			loader: loadJaeger,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.env, tt.value)

			err := tt.loader("TYK_GW", &tt.conf)
			require.Error(t, err)
		})
	}
}
