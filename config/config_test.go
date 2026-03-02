package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/nsf/jsondiff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestDefaultValueAndWriteDefaultConf(t *testing.T) {
	cases := []struct {
		FieldName   string
		EnvVarName  string
		FieldGetter func(*Config) interface{}

		defaultValue  interface{}
		expectedValue interface{}
	}{
		{
			"ListenPort", "TYK_GW_LISTENPORT",
			func(c *Config) interface{} { return c.ListenPort },
			8080, 9090,
		},
		{
			"DnsCacheEnabled", "TYK_GW_DNSCACHE_ENABLED",
			func(c *Config) interface{} { return c.DnsCache.Enabled },
			false, true,
		},
		{
			"DnsCacheTTL", "TYK_GW_DNSCACHE_TTL",
			func(c *Config) interface{} { return c.DnsCache.TTL },
			int64(3600), int64(300),
		},
		{
			"CheckInterval", "TYK_GW_DNSCACHE_CHECKINTERVAL",
			func(c *Config) interface{} { return c.DnsCache.CheckInterval },
			int64(60),
			int64(60), //CheckInterval shouldn't be configured from *.conf and env var
		},
		{
			"CheckMultipleIPsHandleStrategy", "TYK_GW_DNSCACHE_MULTIPLEIPSHANDLESTRATEGY",
			func(c *Config) interface{} { return c.DnsCache.MultipleIPsHandleStrategy },
			NoCacheStrategy,
			RandomStrategy,
		},
		{
			"CertificateExpiryMonitorWarningThresholdDays", "TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_WARNINGTHRESHOLDDAYS",
			func(c *Config) interface{} { return c.Security.CertificateExpiryMonitor.WarningThresholdDays },
			int(30), int(15),
		},
		{
			"CertificateExpiryMonitorCheckCooldownSeconds", "TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_CHECKCOOLDOWNSECONDS",
			func(c *Config) interface{} { return c.Security.CertificateExpiryMonitor.CheckCooldownSeconds },
			int(3600), int(1800),
		},
		{
			"CertificateExpiryMonitorEventCooldownSeconds", "TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_EVENTCOOLDOWNSECONDS",
			func(c *Config) interface{} { return c.Security.CertificateExpiryMonitor.EventCooldownSeconds },
			86400, 43200,
		},
	}

	for _, tc := range cases {
		t.Run(tc.FieldName, func(t *testing.T) {
			conf := &Config{}
			os.Unsetenv(tc.EnvVarName)
			defer os.Unsetenv(tc.EnvVarName)
			if err := WriteDefault("", conf); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.FieldGetter(conf), tc.defaultValue) {
				t.Fatalf("Expected %v to be set to its default %v, but got %v", tc.FieldName, tc.defaultValue, tc.FieldGetter(conf))
			}
			expectedValue := fmt.Sprint(tc.expectedValue)
			t.Setenv(tc.EnvVarName, expectedValue)
			defer func() {
				os.Unsetenv(tc.EnvVarName)
			}()
			if err := WriteDefault("", conf); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.FieldGetter(conf), tc.expectedValue) {
				t.Fatalf("Expected %s to be set to %v, but got %v", tc.FieldName, tc.expectedValue, tc.FieldGetter(conf))
			}
		})
	}
}

func TestConfigFiles(t *testing.T) {
	dir, err := ioutil.TempDir("", "tyk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	conf := &Config{}
	path1 := filepath.Join(dir, "tyk1.conf")
	path2 := filepath.Join(dir, "tyk2.conf")

	if err := WriteDefault(path1, conf); err != nil {
		t.Fatal(err)
	}
	if conf.ListenPort != 8080 {
		t.Fatalf("Expected ListenPort to be set to its default")
	}
	bs, _ := ioutil.ReadFile(path1)
	if !strings.Contains(string(bs), "8080") {
		t.Fatalf("Expected 8080 to be in the written conf file")
	}
	os.Remove(path1)

	paths := []string{path1, path2}
	// should write default config to path1 and return nil
	if err := Load(paths, conf); err != nil {
		t.Fatalf("Load with no existing configs errored")
	}
	if _, err := os.Stat(path1); err != nil {
		t.Fatalf("Load with no configs did not write a default config file")
	}
	if _, err := os.Stat(path2); err == nil {
		t.Fatalf("Load with no configs wrote too many default config files")
	}
	if conf.Private.OriginalPath != path1 {
		t.Fatalf("OriginalPath was not set properly")
	}

	// both exist, we use path1
	os.Link(path1, path2)
	if err := Load(paths, conf); err != nil {
		t.Fatalf("Load with an existing config errored")
	}
	if conf.Private.OriginalPath != path1 {
		t.Fatalf("OriginalPath was not set properly")
	}

	// path2 exists but path1 doesn't
	os.Remove(path1)
	if err := Load(paths, conf); err != nil {
		t.Fatalf("Load with an existing config errored")
	}
	if _, err := os.Stat(path1); err == nil {
		t.Fatalf("Load with a config wrote a default config file")
	}
	if conf.Private.OriginalPath != path2 {
		t.Fatalf("OriginalPath was not set properly")
	}

	// path1 exists but is invalid
	os.Remove(path2)
	ioutil.WriteFile(path1, []byte("{"), 0644)
	if err := Load(paths, conf); err == nil {
		t.Fatalf("Load with an invalid config did not error")
	}
}

func TestConfig_GetEventTriggers(t *testing.T) {

	assertFunc := func(t *testing.T, config string, expected string) {
		t.Helper()
		conf := &Config{}

		f, err := ioutil.TempFile("", "tyk.conf")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		_, err = f.Write([]byte(config))
		if err != nil {
			t.Fatal(err)
		}

		paths := []string{f.Name()}

		if err := Load(paths, conf); err != nil {
			t.Fatal(err)
		}

		triggers := conf.GetEventTriggers()

		if _, ok := triggers[apidef.TykEvent(expected)]; !ok || len(triggers) != 1 {
			t.Fatal("Config is not loaded correctly")
		}
	}

	t.Run("Deprecated configuration", func(t *testing.T) {
		deprecated := `{"event_trigers_defunct": {"deprecated": []}}`
		assertFunc(t, deprecated, "deprecated")
	})

	t.Run("Current configuration", func(t *testing.T) {
		current := `{"event_triggers_defunct": {"current": []}}`
		assertFunc(t, current, "current")
	})

	t.Run("Both configured", func(t *testing.T) {
		both := `{"event_trigers_defunct": {"deprecated": []}, "event_triggers_defunct": {"current": []}}`
		assertFunc(t, both, "current")
	})

}

func TestLoad_tracing(t *testing.T) {
	dir, err := ioutil.TempDir("", "tyk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Run("Read and write config with tracing", func(t *testing.T) {
		files := []string{"testdata/jaeger.json", "testdata/zipkin.json"}
		for _, f := range files {
			t.Run(f, func(t *testing.T) {
				var c Config
				err = Load([]string{f}, &c)
				if err != nil {
					t.Fatal(err)
				}
				o := filepath.Join(
					filepath.Dir(f),
					"expect."+filepath.Base(f),
				)
				expect, err := ioutil.ReadFile(o)
				if err != nil {
					t.Fatal(err)
				}
				got, err := json.MarshalIndent(c.Tracer.Options, "", "    ")
				if err != nil {
					t.Fatal(err)
				}
				diff, s := jsondiff.Compare(expect, got, &jsondiff.Options{
					PrintTypes: true,
				})
				if diff == jsondiff.NoMatch {
					t.Error(s)
				}
			})
		}
	})
	t.Run("Env only", func(t *testing.T) {
		type env struct {
			name, value string
		}
		sample := []struct {
			file string
			env  []env
		}{
			{"testdata/env.jaeger.json", []env{
				{"TYK_GW_TRACER_OPTIONS_SERVICENAME", "jaeger-test-service"},
			}},
			{"testdata/env.zipkin.json", []env{
				{"TYK_GW_TRACER_OPTIONS_REPORTER_URL", "http://example.com"},
				{"TYK_GW_TRACER_OPTIONS_REPORTER_BATCHSIZE", "10"},
				{"TYK_GW_TRACER_OPTIONS_REPORTER_MAXBACKLOG", "20"},
				{"TYK_GW_TRACER_OPTIONS_SAMPLER_NAME", "boundary"},
				{"TYK_GW_TRACER_OPTIONS_SAMPLER_RATE", "10.1"},
				{"TYK_GW_TRACER_OPTIONS_SAMPLER_SALT", "10"},
				{"TYK_GW_TRACER_OPTIONS_SAMPLER_MOD", "12"},
			}},
		}
		for _, v := range sample {
			t.Run(v.file, func(t *testing.T) {
				for _, e := range v.env {
					t.Setenv(e.name, e.value)
				}
				defer func() {
					for _, e := range v.env {
						os.Unsetenv(e.name)
					}
				}()
				var c Config
				err = Load([]string{v.file}, &c)
				if err != nil {
					t.Fatal(err)
				}
				o := filepath.Join(
					filepath.Dir(v.file),
					"expect."+filepath.Base(v.file),
				)
				expect, err := ioutil.ReadFile(o)
				if err != nil {
					t.Fatal(err)
				}
				got, err := json.MarshalIndent(c.Tracer.Options, "", "    ")
				if err != nil {
					t.Fatal(err)
				}
				diff, s := jsondiff.Compare(expect, got, &jsondiff.Options{
					PrintTypes: true,
				})
				if diff == jsondiff.NoMatch {
					t.Error(s)
				}
			})
		}
	})
}

func TestCustomCertsDataDecoder(t *testing.T) {
	var c Config
	t.Setenv("TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES", "[{\"domain_name\":\"testCerts\"}]")
	err := envconfig.Process("TYK_GW", &c)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, c.HttpServerOptions.Certificates, 1, "TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES should have len 1")
	assert.Equal(t, "testCerts", c.HttpServerOptions.Certificates[0].Name, "TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES domain_name should be equals to testCerts")
}

// TestSecretsDecoder tests env variable decoding for TYK_GW_SECRETS.
// It confirms that key pairs should be provided as a comma separated
// list of keys and values, additionally separated by `:` (colon).
func TestSecretsDecoder(t *testing.T) {
	var c Config
	t.Setenv("TYK_GW_SECRETS", "key:value,key2:/value2")
	err := envconfig.Process("TYK_GW", &c)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"key":  "value",
		"key2": "/value2",
	}

	assert.Equal(t, want, c.Secrets)
}

func TestPortsWhiteListDecoder(t *testing.T) {
	var c Config

	//testing invalid value
	t.Setenv("TYK_GW_PORTWHITELIST", "invalid-value")

	httpWhiteList, ok := c.PortWhiteList["http"]
	assert.False(t, ok)
	assert.Empty(t, httpWhiteList)

	tlsWhiteList, ok := c.PortWhiteList["tls"]
	assert.False(t, ok)
	assert.Empty(t, tlsWhiteList)

	//testing empty value
	t.Setenv("TYK_GW_PORTWHITELIST", "")

	httpWhiteList, ok = c.PortWhiteList["http"]
	assert.False(t, ok)
	assert.Empty(t, httpWhiteList)

	tlsWhiteList, ok = c.PortWhiteList["tls"]
	assert.False(t, ok)
	assert.Empty(t, tlsWhiteList)

	//testing real value
	t.Setenv("TYK_GW_PORTWHITELIST", "{\"http\":{\"ranges\":[{\"from\":8000,\"to\":9000}]},\"tls\":{\"ports\":[6000,6015]}}")

	err := envconfig.Process("TYK_GW", &c)
	assert.NoError(t, err)

	httpWhiteList, ok = c.PortWhiteList["http"]
	assert.True(t, ok, "expected to have http key in PortWhiteList")

	assert.Len(t, httpWhiteList.Ports, 0, "http should have 0 Ports")
	assert.Len(t, httpWhiteList.Ranges, 1, "http should have 1 Ranges")

	assert.Equal(t, 8000, httpWhiteList.Ranges[0].From, "http Range From should be equals to 8000")
	assert.Equal(t, 9000, httpWhiteList.Ranges[0].To, "http Range To should be equals to 9000")

	tlsWhiteList, ok = c.PortWhiteList["tls"]
	assert.True(t, ok, "expected to have tls key in PortWhiteList")
	assert.Len(t, tlsWhiteList.Ports, 2, "tls should have 2 Ports")
	assert.Len(t, tlsWhiteList.Ranges, 0, "tls should have 0 Ranges")

	assert.Contains(t, tlsWhiteList.Ports, 6000, "tls should have 6000 port")
	assert.Contains(t, tlsWhiteList.Ports, 6015, "tls should have 6015 port")
}

func TestCertificateExpiryMonitorConfig(t *testing.T) {
	dir, err := ioutil.TempDir("", "tyk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	t.Run("Read and write config with certificate expiry monitor", func(t *testing.T) {
		// Test different configuration scenarios with descriptive file names:
		// - warning_1day_check_1sec_event_1sec_minimal: edge cases with minimum allowed values
		// Note: Reduced test files to essential scenarios only
		files := []string{
			"testdata/cert_monitor_warning_1day_check_1sec_event_1sec_minimal.json",
		}
		for _, f := range files {
			t.Run(f, func(t *testing.T) {
				var c Config
				err = Load([]string{f}, &c)
				if err != nil {
					t.Fatal(err)
				}
				o := filepath.Join(
					filepath.Dir(f),
					"expect."+filepath.Base(f),
				)
				expect, err := ioutil.ReadFile(o)
				if err != nil {
					t.Fatal(err)
				}

				got, err := json.MarshalIndent(c.Security.CertificateExpiryMonitor, "", "    ")
				if err != nil {
					t.Fatal(err)
				}

				diff, s := jsondiff.Compare(expect, got, &jsondiff.Options{
					PrintTypes: true,
				})

				if diff == jsondiff.NoMatch {
					t.Error(s)
				}
			})
		}
	})

	t.Run("Environment variable override", func(t *testing.T) {
		// Test environment variable overrides for certificate expiry monitor configuration
		// This verifies that environment variables take precedence over config file values
		// File contains default values that will be overridden by environment variables
		files := []string{"testdata/cert_monitor_defaults_with_env_overrides.json"}
		for _, f := range files {
			t.Run(f, func(t *testing.T) {
				// Set environment variables
				os.Setenv("TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_WARNINGTHRESHOLDDAYS", "7")
				os.Setenv("TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_CHECKCOOLDOWNSECONDS", "900")
				os.Setenv("TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_EVENTCOOLDOWNSECONDS", "21600")

				defer func() {
					os.Unsetenv("TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_WARNINGTHRESHOLDDAYS")
					os.Unsetenv("TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_CHECKCOOLDOWNSECONDS")
					os.Unsetenv("TYK_GW_SECURITY_CERTIFICATEEXPIRYMONITOR_EVENTCOOLDOWNSECONDS")

				}()

				var c Config

				err = Load([]string{f}, &c)
				if err != nil {
					t.Fatal(err)
				}

				o := filepath.Join(
					filepath.Dir(f),
					"expect."+filepath.Base(f),
				)

				expect, err := ioutil.ReadFile(o)
				if err != nil {
					t.Fatal(err)
				}

				got, err := json.MarshalIndent(c.Security.CertificateExpiryMonitor, "", "    ")
				if err != nil {
					t.Fatal(err)
				}

				diff, s := jsondiff.Compare(expect, got, &jsondiff.Options{
					PrintTypes: true,
				})

				if diff == jsondiff.NoMatch {
					t.Error(s)
				}
			})
		}
	})

	t.Run("Default values when no configuration provided", func(t *testing.T) {
		// Initialize with default values
		c := Default

		// Process environment variables (but don't override our defaults in this test)
		if err := FillEnv(&c); err != nil {
			t.Fatal(err)
		}

		// Verify default values are set correctly
		expected := CertificateExpiryMonitorConfig{
			WarningThresholdDays: 30,
			CheckCooldownSeconds: 3600,
			EventCooldownSeconds: 86400,
		}

		if c.Security.CertificateExpiryMonitor.WarningThresholdDays != expected.WarningThresholdDays {
			t.Errorf("Expected WarningThresholdDays to be %d, got %d",
				expected.WarningThresholdDays, c.Security.CertificateExpiryMonitor.WarningThresholdDays)
		}

		if c.Security.CertificateExpiryMonitor.CheckCooldownSeconds != expected.CheckCooldownSeconds {
			t.Errorf("Expected CheckCooldownSeconds to be %d, got %d",
				expected.CheckCooldownSeconds, c.Security.CertificateExpiryMonitor.CheckCooldownSeconds)
		}

		if c.Security.CertificateExpiryMonitor.EventCooldownSeconds != expected.EventCooldownSeconds {
			t.Errorf("Expected EventCooldownSeconds to be %d, got %d",
				expected.EventCooldownSeconds, c.Security.CertificateExpiryMonitor.EventCooldownSeconds)
		}
	})
}

func TestOpenTelemetryConfig(t *testing.T) {
	t.Run("JSON parsing", func(t *testing.T) {
		var c Config
		err := Load([]string{"testdata/opentelemetry.json"}, &c)
		require.NoError(t, err)

		otelCfg := c.OpenTelemetry
		assert.True(t, otelCfg.Enabled)
		assert.Equal(t, "grpc", otelCfg.Exporter)
		assert.Equal(t, "collector.example.com:4317", otelCfg.Endpoint)
		assert.Equal(t, 5, otelCfg.ConnectionTimeout)
		assert.Equal(t, "my-gateway", otelCfg.ResourceName)
		assert.Equal(t, "batch", otelCfg.SpanProcessorType)
		assert.Equal(t, "tracecontext", otelCfg.ContextPropagation)

		// Sampling
		assert.Equal(t, "TraceIDRatioBased", otelCfg.Sampling.Type)
		assert.Equal(t, 0.5, otelCfg.Sampling.Rate)
		assert.True(t, otelCfg.Sampling.ParentBased)

		// Metrics
		require.NotNil(t, otelCfg.Metrics.Enabled)
		assert.True(t, *otelCfg.Metrics.Enabled)
		assert.Equal(t, 30, otelCfg.Metrics.ExportInterval)
		assert.Equal(t, "cumulative", otelCfg.Metrics.Temporality)
		assert.Equal(t, 15, otelCfg.Metrics.ShutdownTimeout)

		// Metrics retry
		require.NotNil(t, otelCfg.Metrics.Retry.Enabled)
		assert.True(t, *otelCfg.Metrics.Retry.Enabled)
		assert.Equal(t, 3000, otelCfg.Metrics.Retry.InitialInterval)
		assert.Equal(t, 15000, otelCfg.Metrics.Retry.MaxInterval)
		assert.Equal(t, 30000, otelCfg.Metrics.Retry.MaxElapsedTime)
	})

	t.Run("JSON round-trip preserves inline embedding", func(t *testing.T) {
		var c Config
		err := Load([]string{"testdata/opentelemetry.json"}, &c)
		require.NoError(t, err)

		got, err := json.MarshalIndent(c.OpenTelemetry, "", "    ")
		require.NoError(t, err)

		expect, err := os.ReadFile("testdata/expect.opentelemetry.json")
		require.NoError(t, err)

		diff, s := jsondiff.Compare(expect, got, &jsondiff.Options{PrintTypes: true})
		if diff == jsondiff.NoMatch {
			t.Errorf("OpenTelemetry JSON mismatch:\n%s", s)
		}
	})

	t.Run("env var override", func(t *testing.T) {
		t.Setenv("TYK_GW_OPENTELEMETRY_ENABLED", "true")
		t.Setenv("TYK_GW_OPENTELEMETRY_EXPORTER", "grpc")
		t.Setenv("TYK_GW_OPENTELEMETRY_ENDPOINT", "otel-collector:4317")
		t.Setenv("TYK_GW_OPENTELEMETRY_CONNECTIONTIMEOUT", "10")
		t.Setenv("TYK_GW_OPENTELEMETRY_SAMPLING_TYPE", "AlwaysOn")
		t.Setenv("TYK_GW_OPENTELEMETRY_METRICS_EXPORTINTERVAL", "45")

		var c Config
		err := Load([]string{"testdata/opentelemetry_env_override.json"}, &c)
		require.NoError(t, err)

		// Env vars should override file values
		assert.True(t, c.OpenTelemetry.Enabled, "enabled should be overridden to true")
		assert.Equal(t, "grpc", c.OpenTelemetry.Exporter, "exporter should be overridden")
		assert.Equal(t, "otel-collector:4317", c.OpenTelemetry.Endpoint, "endpoint should be overridden")
		assert.Equal(t, 10, c.OpenTelemetry.ConnectionTimeout, "connection_timeout should be overridden")
		assert.Equal(t, "AlwaysOn", c.OpenTelemetry.Sampling.Type, "sampling type should be overridden")
		assert.Equal(t, 45, c.OpenTelemetry.Metrics.ExportInterval, "metrics export_interval should be overridden")
	})

	t.Run("env var only (no config file)", func(t *testing.T) {
		t.Setenv("TYK_GW_OPENTELEMETRY_ENABLED", "true")
		t.Setenv("TYK_GW_OPENTELEMETRY_EXPORTER", "http")
		t.Setenv("TYK_GW_OPENTELEMETRY_ENDPOINT", "localhost:4318")

		var c Config
		err := envconfig.Process("TYK_GW", &c)
		require.NoError(t, err)

		assert.True(t, c.OpenTelemetry.Enabled)
		assert.Equal(t, "http", c.OpenTelemetry.Exporter)
		assert.Equal(t, "localhost:4318", c.OpenTelemetry.Endpoint)
	})

	t.Run("inline JSON embedding produces flat structure", func(t *testing.T) {
		// Verify that json:",inline" on the embedded BaseOpenTelemetry
		// does not produce a nested "BaseOpenTelemetry" key in JSON output.
		var c Config
		err := Load([]string{"testdata/opentelemetry.json"}, &c)
		require.NoError(t, err)

		b, err := json.Marshal(c.OpenTelemetry)
		require.NoError(t, err)

		var raw map[string]interface{}
		require.NoError(t, json.Unmarshal(b, &raw))

		// "enabled" should be a top-level key, not nested under "BaseOpenTelemetry"
		_, hasEnabled := raw["enabled"]
		assert.True(t, hasEnabled, "expected 'enabled' as top-level JSON key")

		_, hasBase := raw["BaseOpenTelemetry"]
		assert.False(t, hasBase, "BaseOpenTelemetry should not appear as a JSON key (inline embedding)")
	})
}
