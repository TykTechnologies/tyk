package main

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"
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

func (h *HeaderTransform) Init(c interface{}, spec *APISpec) error {
	if err := mapstructure.Decode(c, &h.config); err != nil {
		return err
	}
	h.Spec = spec
	return nil
}

func (h *HeaderTransform) HandleResponse(rw http.ResponseWriter,
	res *http.Response, req *http.Request, ses *SessionState) error {

	// Parse target_host parameter from configuration
	target_url, err := url.Parse(h.config.RevProxyTransform.Target_host)
	if err != nil {
		return err
	}

	for _, v := range h.config.RevProxyTransform.Headers {
		// check if header is present and its value is not empty
		if len(res.Header[v]) == 0 || len(res.Header[v][0]) == 0 {
			continue
		}
		// Replace scheme
		newHeaderValue := strings.Replace(
			res.Header[v][0], h.Spec.Target.Scheme, target_url.Scheme, -1)
		// Replace host
		newHeaderValue = strings.Replace(
			newHeaderValue, h.Spec.Target.Host, target_url.Host, -1)
		// Transform path
		if h.Spec.Proxy.StripListenPath {
			if len(h.Spec.Target.Path) != 0 {
				newHeaderValue = strings.Replace(
					newHeaderValue, h.Spec.Target.Path,
					h.Spec.Proxy.ListenPath, -1)
			} else {
				newHeaderValue = strings.Replace(
					newHeaderValue, req.URL.Path,
					h.Spec.Proxy.ListenPath+req.URL.Path, -1)
			}
		} else {
			if len(h.Spec.Target.Path) != 0 {
				newHeaderValue = strings.Replace(
					newHeaderValue, h.Spec.Target.Path,
					"/", -1)
			}
		}
		res.Header[v][0] = newHeaderValue
	}
	return nil
}
