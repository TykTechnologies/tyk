package gateway

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

type RevProxyTransform struct {
	Headers     []string // List of HTTP headers to be modified
	Target_host string   // Target host for reverse proxy
}

type HeaderTransformOptions struct {
	RevProxyTransform RevProxyTransform `mapstructure:"rev_proxy_header_cleanup" bson:"rev_proxy_header_cleanup" json:"rev_proxy_header_cleanup"`
}

type HeaderTransform struct {
	Spec   *APISpec
	config HeaderTransformOptions
}

func (HeaderTransform) Name() string {
	return "HeaderTransform"
}

func (h *HeaderTransform) Init(c interface{}, spec *APISpec) error {
	if err := mapstructure.Decode(c, &h.config); err != nil {
		return err
	}
	h.Spec = spec
	return nil
}

func (h *HeaderTransform) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *HeaderTransform) HandleResponse(rw http.ResponseWriter,
	res *http.Response, req *http.Request, ses *user.SessionState) error {

	// Parse target_host parameter from configuration
	target_url, err := url.Parse(h.config.RevProxyTransform.Target_host)
	if err != nil {
		return err
	}
	ignoreCanonical := config.Global().IgnoreCanonicalMIMEHeaderKey
	for _, name := range h.config.RevProxyTransform.Headers {
		// check if header is present and its value is not empty
		val := res.Header.Get(name)
		if val == "" {
			continue
		}
		// Replace scheme
		val = strings.ReplaceAll(val, h.Spec.target.Scheme, target_url.Scheme)
		// Replace host
		val = strings.ReplaceAll(val, h.Spec.target.Host, target_url.Host)
		// Transform path
		if h.Spec.Proxy.StripListenPath {
			if len(h.Spec.target.Path) != 0 {
				val = strings.ReplaceAll(val, h.Spec.target.Path,
					h.Spec.Proxy.ListenPath)
			} else {
				val = strings.ReplaceAll(val, req.URL.Path,
					h.Spec.Proxy.ListenPath+req.URL.Path)
			}
		} else {
			if len(h.Spec.target.Path) != 0 {
				val = strings.ReplaceAll(val, h.Spec.target.Path, "/")
			}
		}
		setCustomHeader(res.Header, name, val, ignoreCanonical)
	}
	return nil
}
