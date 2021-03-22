package config

import (
	"encoding/json"
	"fmt"

	"github.com/kelseyhightower/envconfig"
	jaeger "github.com/uber/jaeger-client-go/config"
	"gopkg.in/yaml.v3"
)

// ZipkinConfig configuration options used to initialize openzipkin opentracing
// client.
type ZipkinConfig struct {
	Reporter Reporter `json:"reporter"`
	Sampler  Sampler  `json:"sampler"`
}

type Reporter struct {
	// URL connection url to the zipkin server
	URL        string `json:"url"`
	BatchSize  int    `json:"batch_size"`
	MaxBacklog int    `json:"max_backlog"`
}

type Sampler struct {
	//Name is the name of the sampler to use. Options are
	//
	// 	"boundary"
	// is appropriate for high-traffic instrumentation who
	// provision random trace ids, and make the sampling decision only once.
	// It defends against nodes in the cluster selecting exactly the same ids.
	//
	//	"count"
	// is appropriate for low-traffic instrumentation or
	// those who do not provision random trace ids. It is not appropriate for
	// collectors as the sampling decision isn't idempotent (consistent based
	// on trace id).
	//
	// "mod"
	// provides a generic type Sampler
	Name string `json:"name"`
	//Rate is used by both "boundary" and "count" samplers
	Rate float64 `json:"rate"`
	//Salt is used by "boundary" sampler
	Salt int64 `json:"salt"`
	// Mod is only used when sampler is mod
	Mod uint64 `json:"mod"`
}

// DecodeJSON marshals src to json and tries to unmarshal the result into
// dest.
func DecodeJSON(dest, src interface{}) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}

func DecodeYAML(dest, src interface{}) error {
	b, err := yaml.Marshal(src)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, dest)
}

// loadZipkin tries to lad zipkin configuration from environment variables.
//
// list of zipkin configuration env variables
//
// TYK_GW_TRACER_OPTIONS_REPORTER_URL
// TYK_GW_TRACER_OPTIONS_REPORTER_BATCHSIZE
// TYK_GW_TRACER_OPTIONS_REPORTER_MAXBACKLOG
// TYK_GW_TRACER_OPTIONS_SAMPLER_NAME
// TYK_GW_TRACER_OPTIONS_SAMPLER_RATE
// TYK_GW_TRACER_OPTIONS_SAMPLER_SALT
// TYK_GW_TRACER_OPTIONS_SAMPLER_MOD
func loadZipkin(prefix string, c *Config) error {
	if c.Tracer.Name != "zipkin" {
		return nil
	}
	var zip ZipkinConfig
	if err := DecodeJSON(&zip, c.Tracer.Options); err != nil {
		return err
	}
	qualifyPrefix := prefix + "_TRACER_OPTIONS"
	err := envconfig.Process(qualifyPrefix, &zip)
	if err != nil {
		return err
	}
	o := make(map[string]interface{})
	if err := DecodeJSON(&o, zip); err != nil {
		return err
	}
	c.Tracer.Options = o
	return nil
}

// loads jaeger configuration from environment variables.
//
// List of jaeger configuration env vars
//
// TYK_GW_TRACER_OPTIONS_SERVICENAME
// TYK_GW_TRACER_OPTIONS_DISABLED
// TYK_GW_TRACER_OPTIONS_RPCMETRICS
// TYK_GW_TRACER_OPTIONS_TAGS
// TYK_GW_TRACER_OPTIONS_SAMPLER_TYPE
// TYK_GW_TRACER_OPTIONS_SAMPLER_PARAM
// TYK_GW_TRACER_OPTIONS_SAMPLER_SAMPLINGSERVERURL
// TYK_GW_TRACER_OPTIONS_SAMPLER_MAXOPERATIONS
// TYK_GW_TRACER_OPTIONS_SAMPLER_SAMPLINGREFRESHINTERVAL
// TYK_GW_TRACER_OPTIONS_REPORTER_QUEUESIZE
// TYK_GW_TRACER_OPTIONS_REPORTER_BUFFERFLUSHINTERVAL
// TYK_GW_TRACER_OPTIONS_REPORTER_LOGSPANS
// TYK_GW_TRACER_OPTIONS_REPORTER_LOCALAGENTHOSTPORT
// TYK_GW_TRACER_OPTIONS_REPORTER_COLLECTORENDPOINT
// TYK_GW_TRACER_OPTIONS_REPORTER_USER
// TYK_GW_TRACER_OPTIONS_REPORTER_PASSWORD
// TYK_GW_TRACER_OPTIONS_HEADERS_JAEGERDEBUGHEADER
// TYK_GW_TRACER_OPTIONS_HEADERS_JAEGERBAGGAGEHEADER
// TYK_GW_TRACER_OPTIONS_HEADERS_TRACECONTEXTHEADERNAME
// TYK_GW_TRACER_OPTIONS_HEADERS_TRACEBAGGAGEHEADERPREFIX
// TYK_GW_TRACER_OPTIONS_BAGGAGERESTRICTIONS_DENYBAGGAGEONINITIALIZATIONFAILURE
// TYK_GW_TRACER_OPTIONS_BAGGAGERESTRICTIONS_HOSTPORT
// TYK_GW_TRACER_OPTIONS_BAGGAGERESTRICTIONS_REFRESHINTERVAL
// TYK_GW_TRACER_OPTIONS_THROTTLER_HOSTPORT
// TYK_GW_TRACER_OPTIONS_THROTTLER_REFRESHINTERVAL
// TYK_GW_TRACER_OPTIONS_THROTTLER_SYNCHRONOUSINITIALIZATION
func loadJaeger(prefix string, c *Config) error {
	if c.Tracer.Name != "jaeger" {
		return nil
	}
	var j jaeger.Configuration
	if err := DecodeYAML(&j, c.Tracer.Options); err != nil {
		fmt.Printf(" %#v\n ", c.Tracer.Options)
		return err
	}
	qualifyPrefix := prefix + "_TRACER_OPTIONS"
	err := envconfig.Process(qualifyPrefix, &j)
	if err != nil {
		return err
	}
	o := make(map[string]interface{})
	if err := DecodeYAML(&o, j); err != nil {
		return err
	}
	c.Tracer.Options = o
	return nil
}
