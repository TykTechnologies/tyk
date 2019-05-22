package main

import (
	"net/http"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

type HeaderInjectorOptions struct {
	AddHeaders    map[string]string `mapstructure:"add_headers" bson:"add_headers" json:"add_headers"`
	RemoveHeaders []string          `mapstructure:"remove_headers" bson:"remove_headers" json:"remove_headers"`
}

type HeaderInjector struct {
	Spec   *APISpec
	config HeaderInjectorOptions
}

func (h *HeaderInjector) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec
	return mapstructure.Decode(c, &h.config)
}

func (h *HeaderInjector) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	// TODO: This should only target specific paths

	_, versionPaths, _, _ := h.Spec.Version(req)
	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, HeaderInjectedResponse)
	if found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, dKey := range hmeta.DeleteHeaders {
			res.Header.Del(dKey)
		}
		for nKey, nVal := range hmeta.AddHeaders {
			res.Header.Set(nKey, replaceTykVariables(req, nVal, false))
		}
	}

	// Global header options
	for _, n := range h.config.RemoveHeaders {
		res.Header.Del(n)
	}
	for h, v := range h.config.AddHeaders {
		res.Header.Set(h, replaceTykVariables(req, v, false))
	}

	return nil
}
