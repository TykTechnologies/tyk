package config

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	jaeger "github.com/uber/jaeger-client-go/config"
)

func TestLoadZipkin(t *testing.T) {
	base := ZipkinConfig{
		Reporter: Reporter{
			URL:        "repoturl",
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
	t.Run("Returns nil when it is not zipkin config", func(t *testing.T) {
		conf := &Config{}
		err := loadZipkin(envPrefix, conf)
		if err != nil {
			t.Fatal(err)
		}
		if conf.Tracer.Options != nil {
			t.Error("expected options to be nil")
		}
	})
	t.Run("handles nil options", func(t *testing.T) {
		conf := &Config{Tracer: Tracer{Name: "zipkin"}}
		err := loadZipkin(envPrefix, conf)
		if err != nil {
			t.Fatal(err)
		}
		if conf.Tracer.Options != nil {
			t.Error("expected options to be nil")
		}
	})

	t.Run("loads env vars", func(t *testing.T) {
		o := make(map[string]interface{})
		err := DecodeJSON(&o, base)
		if err != nil {
			t.Fatal(err)
		}
		conf := &Config{Tracer: Tracer{Name: "zipkin", Options: o}}
		err = loadZipkin(envPrefix, conf)
		if err != nil {
			t.Fatal(err)
		}
		var got ZipkinConfig
		err = DecodeJSON(&got, conf.Tracer.Options)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(base, got) {
			t.Errorf("expected %#v got %#v", base, got)
		}
	})
}
func TestLoadJaeger(t *testing.T) {
	base := &jaeger.Configuration{ServiceName: "jaeger-test-service"}
	sample := []struct {
		env   string
		value string
	}{
		{"TYK_GW_TRACER_OPTIONS_SERVICENAME", base.ServiceName},
	}
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
	t.Run("Returns nil when it is not jaeger config", func(t *testing.T) {
		conf := &Config{}
		err := loadJaeger(envPrefix, conf)
		if err != nil {
			t.Fatal(err)
		}
		if conf.Tracer.Options != nil {
			t.Error("expected options to be nil")
		}
	})
	t.Run("Handles nil options", func(t *testing.T) {
		conf := &Config{Tracer: Tracer{Name: "jaeger"}}
		err := loadJaeger(envPrefix, conf)
		if err != nil {
			t.Fatal(err)
		}
		if conf.Tracer.Options != nil {
			t.Error("expected options to be nil")
		}
	})

	t.Run("Loads env vars", func(t *testing.T) {
		o := make(map[string]interface{})
		err := DecodeJSON(&o, base)
		if err != nil {
			t.Fatal(err)
		}
		conf := &Config{Tracer: Tracer{Name: "jaeger", Options: o}}
		err = loadJaeger(envPrefix, conf)
		if err != nil {
			t.Fatal(err)
		}
		var got jaeger.Configuration
		err = DecodeJSON(&got, conf.Tracer.Options)
		if err != nil {
			t.Fatal(err)
		}
		if base.ServiceName != got.ServiceName {
			t.Errorf("expected %#v got %#v", base.ServiceName, got.ServiceName)
		}
	})
}
