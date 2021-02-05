package jaeger

import (
	"github.com/uber/jaeger-client-go/config"
	yaml "gopkg.in/yaml.v2"
)

// Load returns jaeger configuration from opts. Please see jaeger configuration
// for details about the key value pairs
//
// https://github.com/jaegertracing/jaeger-client-go/blob/master/config/config.go#L37
func Load(opts map[string]interface{}) (*config.Configuration, error) {
	// The object opts is loaded from json. Instead of decoding every single value
	// by had we marshal to then to yaml.
	//
	// This is possible because the tags are the same for both json and yaml.
	b, err := yaml.Marshal(opts)
	if err != nil {
		return nil, err
	}
	var c config.Configuration
	err = yaml.Unmarshal(b, &c)
	return &c, nil
}
