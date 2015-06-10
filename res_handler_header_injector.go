package main

import (
	"net/http"
	"github.com/mitchellh/mapstructure"
)

type HeaderInjectorOptions struct {
	AddHeaders map[string]string `mapstructure:"add_headers" bson:"add_headers" json:"add_headers"`
	RemoveHeaders []string `mapstructure:"remove_headers" bson:"remove_headers" json:"remove_headers"`
}

type HeaderInjector struct{
	Spec *APISpec
	config HeaderInjectorOptions
}

func (h HeaderInjector) New(c interface{}, spec *APISpec) (TykResponseHandler, error) {
	thisHandler := HeaderInjector{}
	thisModuleConfig := HeaderInjectorOptions{}

	err := mapstructure.Decode(c, &thisModuleConfig)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	
	thisHandler.config = thisModuleConfig
	thisHandler.Spec = spec

	return thisHandler, nil
}

func (h HeaderInjector) HandleResponse(rw http.ResponseWriter, res *http.Response, ses *SessionState) error {
	// TODO: This should only target specific paths
	for _, n := range(h.config.RemoveHeaders) {
		res.Header.Del(n)
	}

	for h, v := range(h.config.AddHeaders) {
		res.Header.Add(h, v)
	}

	return nil
}
