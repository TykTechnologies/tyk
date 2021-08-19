package gateway

import (
	"net/http"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
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

	ignoreCanonical := config.Global().IgnoreCanonicalMIMEHeaderKey
	vInfo, versionPaths, _, _ := h.Spec.Version(req)
	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, HeaderInjectedResponse)
	if found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, dKey := range hmeta.DeleteHeaders {
			res.Header.Del(dKey)
		}
		for nKey, nVal := range hmeta.AddHeaders {
			setCustomHeader(res.Header, nKey, replaceTykVariables(req, nVal, false), ignoreCanonical)
		}
	}

	// Manage global response header options with versionInfo
	for _, key := range vInfo.GlobalResponseHeadersRemove {
		log.Debug("Removing: ", key)
		res.Header.Del(key)
	}

	for key, val := range vInfo.GlobalResponseHeaders {
		log.Debug("Adding: ", key)
		setCustomHeader(res.Header, key, replaceTykVariables(req, val, false), ignoreCanonical)
	}

	// Manage global response header options with response_processors
	for _, n := range h.config.RemoveHeaders {
		res.Header.Del(n)
	}
	for h, v := range h.config.AddHeaders {
		setCustomHeader(res.Header, h, replaceTykVariables(req, v, false), ignoreCanonical)
	}

	return nil
}
