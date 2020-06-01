package config

import (
	"encoding/json"

	"github.com/kelseyhightower/envconfig"
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

// loadZipkin tries to lad zipkin configuration from environment variables.
func loadZipkin(prefix string, c *Config) error {
	if c.Tracer.Name != "zipkin" || c.Tracer.Options == nil {
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
