package gateway

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
	BaseTykResponseHandler
	config HeaderInjectorOptions
}

func (h *HeaderInjector) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (*HeaderInjector) Name() string {
	return "HeaderInjector"
}

func (h *HeaderInjector) Enabled() bool {
	for _, version := range h.Spec.VersionData.Versions {
		if version.GlobalResponseHeadersEnabled() {
			return true
		}

		if version.HasEndpointResHeader() {
			return true
		}
	}

	return false
}

func (h *HeaderInjector) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec
	return mapstructure.Decode(c, &h.config)
}

func (h *HeaderInjector) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *HeaderInjector) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	// TODO: This should only target specific paths
	ignoreCanonical := h.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	vInfo, _ := h.Spec.Version(req)
	versionPaths := h.Spec.RxPaths[vInfo.Name]

	found, meta := h.Spec.CheckSpecMatchesStatus(req, versionPaths, HeaderInjectedResponse)
	if found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, dKey := range hmeta.DeleteHeaders {
			res.Header.Del(dKey)
		}
		for nKey, nVal := range hmeta.AddHeaders {
			setCustomHeader(res.Header, nKey, h.Gw.ReplaceTykVariables(req, nVal, false), ignoreCanonical)
		}
	}

	// Manage global response header options with versionInfo
	if !vInfo.GlobalResponseHeadersDisabled {
		for _, key := range vInfo.GlobalResponseHeadersRemove {
			log.Debug("Removing: ", key)
			res.Header.Del(key)
		}

		for key, val := range vInfo.GlobalResponseHeaders {
			log.Debug("Adding: ", key)
			setCustomHeader(res.Header, key, h.Gw.ReplaceTykVariables(req, val, false), ignoreCanonical)
		}

		// Manage global response header options with response_processors
		for _, n := range h.config.RemoveHeaders {
			res.Header.Del(n)
		}
		for header, v := range h.config.AddHeaders {
			setCustomHeader(res.Header, header, h.Gw.ReplaceTykVariables(req, v, false), ignoreCanonical)
		}
	}

	return nil
}
