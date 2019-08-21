package jaeger

import (
	"encoding/json"
	"reflect"
	"testing"

	jaeger "github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
)

const sampleConfig = `{
    "serviceName": "your_service_name",
    "disabled": false,
    "rpc_metrics": false,
    "tags": null,
    "sampler": {
        "type": "const",
        "param": 1,
        "samplingServerURL": "",
        "maxOperations": 0,
        "samplingRefreshInterval": 0
    },
    "reporter": {
        "queueSize": 0,
        "BufferFlushInterval": 0,
        "logSpans": true,
        "localAgentHostPort": "",
        "collectorEndpoint": "",
        "user": "",
        "password": ""
    },
    "headers": null,
    "baggage_restrictions": null,
    "throttler": null
}`

func TestLoad(t *testing.T) {
	cfg := config.Configuration{
		ServiceName: "your_service_name",
		Sampler: &config.SamplerConfig{
			Type:  jaeger.SamplerTypeConst,
			Param: 1,
		},
		Reporter: &config.ReporterConfig{
			LogSpans: true,
		},
	}
	var o map[string]interface{}
	err := json.Unmarshal([]byte(sampleConfig), &o)
	if err != nil {
		t.Fatal(err)
	}
	loadedConfig, err := Load(o)
	if err != nil {
		t.Fatal(err)
	}
	a := []interface{}{
		cfg.ServiceName, cfg.Disabled,
		cfg.RPCMetrics, cfg.Tags, cfg.Sampler,
		cfg.Reporter, cfg.Headers, cfg.BaggageRestrictions,
	}
	b := []interface{}{
		loadedConfig.ServiceName, loadedConfig.Disabled,
		loadedConfig.RPCMetrics, loadedConfig.Tags,
		loadedConfig.Sampler, loadedConfig.Reporter,
		loadedConfig.Headers, loadedConfig.BaggageRestrictions,
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("expected %v\n got  %v\n", cfg, loadedConfig)
	}
}
