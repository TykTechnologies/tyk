package gateway

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"

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
	BaseTykResponseHandler
	config HeaderTransformOptions
}

func (h *HeaderTransform) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (h *HeaderTransform) Name() string {
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

func replaceHeaderPathPrefix(value, oldPath, newPath string) string {
	rewriteURL := func(raw string) (string, bool) {
		pathStart := -1
		switch {
		case strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//"):
			pathStart = 0
		default:
			authorityStart := -1
			if schemeEnd := strings.Index(raw, "://"); schemeEnd > 0 && !strings.ContainsAny(raw[:schemeEnd], "<> ,;\t") {
				authorityStart = schemeEnd + 3
			} else if strings.HasPrefix(raw, "//") {
				authorityStart = 2
			}
			if authorityStart < 0 {
				return raw, false
			}
			i := strings.IndexAny(raw[authorityStart:], "/?#")
			if i < 0 || raw[authorityStart+i] != '/' {
				return raw, false
			}
			pathStart = authorityStart + i
		}

		path := raw[pathStart:]
		if !strings.HasPrefix(path, oldPath) {
			return raw, false
		}
		return raw[:pathStart] + newPath + raw[pathStart+len(oldPath):], true
	}

	if rewritten, ok := rewriteURL(value); ok {
		return rewritten
	}

	// Link-style headers can contain multiple URL references in angle brackets.
	for offset := 0; offset < len(value); {
		open := strings.IndexByte(value[offset:], '<')
		if open < 0 {
			break
		}
		open += offset
		close := strings.IndexByte(value[open+1:], '>')
		if close < 0 {
			break
		}
		close += open + 1

		resource := value[open+1 : close]
		if rewritten, ok := rewriteURL(resource); ok {
			value = value[:open+1] + rewritten + value[close:]
			close += len(rewritten) - len(resource)
		}
		offset = close + 1
	}

	return value
}

func (h *HeaderTransform) HandleResponse(rw http.ResponseWriter,
	res *http.Response, req *http.Request, ses *user.SessionState) error {

	// Parse target_host parameter from configuration
	target_url, err := url.Parse(h.config.RevProxyTransform.Target_host)
	if err != nil {
		return err
	}
	ignoreCanonical := h.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for _, name := range h.config.RevProxyTransform.Headers {
		// check if header is present and its value is not empty
		val := res.Header.Get(name)
		if val == "" {
			continue
		}
		// Replace scheme
		val = strings.Replace(val, h.Spec.target.Scheme, target_url.Scheme, -1)
		// Replace host
		val = strings.Replace(val, h.Spec.target.Host, target_url.Host, -1)
		// Transform path
		if h.Spec.Proxy.StripListenPath {
			if len(h.Spec.target.Path) != 0 {
				val = replaceHeaderPathPrefix(val, h.Spec.target.Path,
					h.Spec.Proxy.ListenPath)
			} else {
				val = strings.Replace(val, req.URL.Path,
					h.Spec.Proxy.ListenPath+req.URL.Path, -1)
			}
		} else {
			if len(h.Spec.target.Path) != 0 {
				val = replaceHeaderPathPrefix(val, h.Spec.target.Path, "/")
			}
		}
		setCustomHeader(res.Header, name, val, ignoreCanonical)
	}
	return nil
}
