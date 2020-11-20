package jaeger

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	tykconf "github.com/TykTechnologies/tyk/config"
	jaeger "github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
)

const sampleConfig = `{
	"tracing": {
	  "enabled": true,
	  "name": "jaeger",
	  "options": {
		"baggage_restrictions": null,
		"disabled": false,
		"headers": null,
		"reporter": {
		  "BufferFlushInterval": 0,
		  "collectorEndpoint": "",
		  "localAgentHostPort": "jaeger:6831",
		  "logSpans": true,
		  "password": "",
		  "queueSize": 0,
		  "user": ""
		},
		"rpc_metrics": false,
		"sampler": {
		  "maxOperations": 0,
		  "param": 1,
		  "samplingRefreshInterval": 0,
		  "samplingServerURL": "",
		  "type": "const"
		},
		"serviceName": "tyk-gateway",
		"tags": null,
		"throttler": null
	  }
	}
  }
  `

func TestLoad(t *testing.T) {
	dir, err := ioutil.TempDir("", "tyk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	f := filepath.Join(dir, "jaeger.json")
	err = ioutil.WriteFile(f, []byte(sampleConfig), 0600)
	if err != nil {
		t.Fatal(err)
	}
	var c tykconf.Config
	err = tykconf.Load([]string{f}, &c)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Configuration{
		ServiceName: "tyk-gateway",
		Sampler: &config.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
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
