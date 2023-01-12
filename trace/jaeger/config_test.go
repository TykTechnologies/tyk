package jaeger

import (
	"reflect"
	"testing"

	jaeger "github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"

	tykconf "github.com/TykTechnologies/tyk/config"
)

func TestLoad(t *testing.T) {
	f := "testdata/jaeger.json"
	var c tykconf.Config
	err := tykconf.Load([]string{f}, &c)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Configuration{
		ServiceName: "tyk-gateway",
		Sampler: &config.SamplerConfig{
			Type:    jaeger.SamplerTypeConst,
			Param:   1,
			Options: []jaeger.SamplerOption{},
		},
		Reporter: &config.ReporterConfig{
			LogSpans:           true,
			LocalAgentHostPort: "jaeger:6831",
		},
	}

	loadedConfig, err := Load(c.Tracer.Options)
	if err != nil {
		t.Fatal(err)
	}
	e := []struct {
		field  string
		expect interface{}
		got    interface{}
	}{
		{"serviceName", cfg.ServiceName, loadedConfig.ServiceName},
		{"rpc_metrics", cfg.RPCMetrics, loadedConfig.RPCMetrics},
		{"sampler", cfg.Sampler, loadedConfig.Sampler},
		{"reporter", cfg.Reporter, loadedConfig.Reporter},
	}
	for _, v := range e {
		if !reflect.DeepEqual(v.expect, v.got) {
			t.Errorf("%v: expected %#v got %#v", v.field, v.expect, v.got)
		}
	}
}
