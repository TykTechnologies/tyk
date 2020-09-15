package config

import (
	"fmt"
	"os"
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
		conf := &Config{Tracer: Tracer{Name: "zipkin"}}
		err := loadZipkin(envPrefix, conf)
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

func TestLoadJaeger(t *testing.T) {
	base := &jaeger.Configuration{ServiceName: "jaeger-test-service"}
	sample := []struct {
		env   string
		value string
	}{
		{"TYK_GW_TRACER_OPTIONS_SERVICENAME", base.ServiceName},
	}
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

		conf := &Config{Tracer: Tracer{Name: "jaeger"}}
		err := loadJaeger(envPrefix, conf)
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
