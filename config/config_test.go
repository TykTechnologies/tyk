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
			os.Setenv(tc.EnvVarName, expectedValue)
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
	if conf.OriginalPath != path1 {
		t.Fatalf("OriginalPath was not set properly")
	}

	// both exist, we use path1
	os.Link(path1, path2)
	if err := Load(paths, conf); err != nil {
		t.Fatalf("Load with an existing config errored")
	}
	if conf.OriginalPath != path1 {
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
	if conf.OriginalPath != path2 {
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

	assert := func(t *testing.T, config string, expected string) {
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
		assert(t, deprecated, "deprecated")
	})

	t.Run("Current configuration", func(t *testing.T) {
		current := `{"event_triggers_defunct": {"current": []}}`
		assert(t, current, "current")
	})

	t.Run("Both configured", func(t *testing.T) {
		both := `{"event_trigers_defunct": {"deprecated": []}, "event_triggers_defunct": {"current": []}}`
		assert(t, both, "current")
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
					os.Setenv(e.name, e.value)
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
	os.Setenv("TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES", "[{\"domain_name\":\"testCerts\"}]")
	err := envconfig.Process("TYK_GW", &c)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, c.HttpServerOptions.Certificates, 1, "TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES should have len 1")
	assert.Equal(t, "testCerts", c.HttpServerOptions.Certificates[0].Name, "TYK_GW_HTTPSERVEROPTIONS_CERTIFICATES domain_name should be equals to testCerts")

}

func TestPortsWhiteListDecoder(t *testing.T) {
	var c Config

	//testing invalid value
	err := os.Setenv("TYK_GW_PORTWHITELIST", "invalid-value")
	assert.NoError(t, err)

	httpWhiteList, ok := c.PortWhiteList["http"]
	assert.False(t, ok)
	assert.Empty(t, httpWhiteList)

	tlsWhiteList, ok := c.PortWhiteList["tls"]
	assert.False(t, ok)
	assert.Empty(t, tlsWhiteList)

	//testing empty value
	err = os.Setenv("TYK_GW_PORTWHITELIST", "")
	assert.NoError(t, err)

	httpWhiteList, ok = c.PortWhiteList["http"]
	assert.False(t, ok)
	assert.Empty(t, httpWhiteList)

	tlsWhiteList, ok = c.PortWhiteList["tls"]
	assert.False(t, ok)
	assert.Empty(t, tlsWhiteList)

	//testing real value
	err = os.Setenv("TYK_GW_PORTWHITELIST", "{\"http\":{\"ranges\":[{\"from\":8000,\"to\":9000}]},\"tls\":{\"ports\":[6000,6015]}}")
	assert.NoError(t, err)

	err = envconfig.Process("TYK_GW", &c)
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
