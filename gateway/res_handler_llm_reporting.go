package gateway

import (
	"net/http"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
)

type LLMResponseReporterOptions struct {
}

type LLMResponseReporter struct {
	BaseTykResponseHandler
	config HeaderInjectorOptions
}

func (h *LLMResponseReporter) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (*LLMResponseReporter) Name() string {
	return "LLMResponseReporter"
}

func (h *LLMResponseReporter) Enabled() bool {
	for _, v := range h.Spec.Tags {
		if v == "llm" {
			return true
		}
	}
}

func (h *LLMResponseReporter) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec
	return mapstructure.Decode(c, &h.config)
}

func (h *LLMResponseReporter) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *LLMResponseReporter) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
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
			setCustomHeader(res.Header, nKey, h.Gw.replaceTykVariables(req, nVal, false), ignoreCanonical)
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
			setCustomHeader(res.Header, key, h.Gw.replaceTykVariables(req, val, false), ignoreCanonical)
		}

		// Manage global response header options with response_processors
		for _, n := range h.config.RemoveHeaders {
			res.Header.Del(n)
		}
		for header, v := range h.config.AddHeaders {
			setCustomHeader(res.Header, header, h.Gw.replaceTykVariables(req, v, false), ignoreCanonical)
		}
	}

	return nil
}
