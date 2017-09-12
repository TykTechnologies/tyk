package main

import (
	"net/http"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/apidef"
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
	if err := mapstructure.Decode(c, &h.config); err != nil {
		return err
	}
	return nil
}

func (h *HeaderInjector) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {
	// TODO: This should only target specific paths

	_, versionPaths, _, _ := h.Spec.Version(req)
	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, HeaderInjectedResponse)
	if found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, dKey := range hmeta.DeleteHeaders {
			res.Header.Del(dKey)
		}
		for nKey, nVal := range hmeta.AddHeaders {
			res.Header.Set(nKey, nVal)
		}
	}

	// Global header options
	for _, n := range h.config.RemoveHeaders {
		res.Header.Del(n)
	}
	for h, v := range h.config.AddHeaders {
		res.Header.Set(h, v)
	}

	return nil
}
