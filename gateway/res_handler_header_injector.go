package gateway

import (
	"net/http"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/v3/apidef"
	"github.com/TykTechnologies/tyk/v3/user"
)

type HeaderInjectorOptions struct {
	AddHeaders    map[string]string `mapstructure:"add_headers" bson:"add_headers" json:"add_headers"`
	RemoveHeaders []string          `mapstructure:"remove_headers" bson:"remove_headers" json:"remove_headers"`
}

type HeaderInjector struct {
	Spec   *APISpec
	config HeaderInjectorOptions
}

func (HeaderInjector) Name() string {
	return "HeaderInjector"
}
func (h *HeaderInjector) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec
	return mapstructure.Decode(c, &h.config)
}

func (h *HeaderInjector) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *HeaderInjector) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	// TODO: This should only target specific paths

	vInfo, versionPaths, _, _ := h.Spec.Version(req)
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

	// Manage global response header options with versionInfo
	for _, key := range vInfo.GlobalResponseHeadersRemove {
		log.Debug("Removing: ", key)
		res.Header.Del(key)
	}

	for key, val := range vInfo.GlobalResponseHeaders {
		log.Debug("Adding: ", key)
		res.Header.Set(key, replaceTykVariables(req, val, false))
	}

	// Manage global response header options with response_processors
	for _, n := range h.config.RemoveHeaders {
		res.Header.Del(n)
	}
	for h, v := range h.config.AddHeaders {
		res.Header.Set(h, replaceTykVariables(req, v, false))
	}

	return nil
}
