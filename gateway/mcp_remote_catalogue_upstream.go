package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/service/core"
)

// remoteMCPCatalogueClient returns the HTTP client of a catalogue check and
// a function that releases its connections.
//
// The transport is the proxy's own upstream transport (see httpTransport),
// with h2c targets marked as WrappedServeHTTP marks them:
// the API's proxy URL or the environment proxy, TLS versions and ciphers,
// SSLInsecureSkipVerify, certificate pinning, the forced common-name check,
// HTTP/2 and h2c settings, the DNS cache, plus the upstream mTLS certificate
// for the target host. The client never follows redirects, so upstream
// credentials cannot be sent to another host and the check cannot be steered
// to other addresses; a 3xx is handled like an unreachable upstream.
func (gw *Gateway) remoteMCPCatalogueClient(spec *APISpec, logger *logrus.Entry) (*http.Client, func(), error) {
	target, err := http.NewRequest(http.MethodPost, spec.Proxy.TargetURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	proxy := &ReverseProxy{TykAPISpec: spec, Gw: gw, logger: logger}
	roundTripper := proxy.httpTransport(proxyTimeout(spec), target, target)
	if transport := roundTripper.transport; transport != nil {
		if cert := gw.getUpstreamCertificate(target.URL.Host, spec); cert != nil {
			transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}
			transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return cert, nil
			}
		}
		if spec.Proxy.Transport.SSLForceCommonNameCheck || gw.GetConfig().SSLForceCommonNameCheck {
			// A proxy lookup error fails the check's request itself, in the transport.
			if proxyURL, proxyErr := transport.Proxy(target); proxyErr == nil && proxyURL != nil {
				host, _, splitErr := net.SplitHostPort(target.URL.Host)
				if splitErr != nil {
					host = target.URL.Host
				}
				proxy.setCommonNameVerifyPeerCertificate(transport.TLSClientConfig, host)
			}
		}
	}

	client := &http.Client{
		Transport:     remoteMCPCatalogueRoundTripper{roundTripper},
		Timeout:       remoteMCPCatalogueTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client, roundTripper.Retire, nil
}

// remoteMCPCatalogueHeader returns the request headers a catalogue check
// sends: the API's static global request headers, then the upstream
// credential the proxy would add.
//
// Global header values that use $tyk_context or $tyk_meta are skipped,
// because they need a client request or session; secret references are
// resolved. Upstream basic auth and upstream OAuth (client credentials and
// password) run through the proxy's own middleware, so the OAuth token is
// fetched, cached and shared with the proxy, and both are Enterprise Edition
// features exactly as on the proxy. Credentials that need a client request
// are not available: the MCP OAuth broker, request signing, credentials
// forwarded from the client and endpoint-level header injection.
func (gw *Gateway) remoteMCPCatalogueHeader(ctx context.Context, spec *APISpec, logger *logrus.Entry) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, spec.Proxy.TargetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	h := http.Header{}

	if version, _ := spec.Version(req); version != nil && !version.GlobalHeadersDisabled {
		ignoreCanonical := gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
		for name, value := range version.GlobalHeaders {
			if strings.Contains(value, contextLabel) || strings.Contains(value, metaLabel) {
				logger.WithField("header", name).Debug("Global request header needs a client request; it is not sent with the MCP catalogue check")
				continue
			}
			setCustomHeader(h, name, gw.ReplaceTykVariables(req, value, false), ignoreCanonical)
		}
	}

	auth := spec.UpstreamAuth
	if !auth.IsEnabled() || !shouldLoadGenericUpstreamAuth(spec) {
		return h, nil
	}
	if !upstreamAuthAvailable {
		// The proxy chain already reports that upstream auth needs the
		// Enterprise Edition; the proxy sends none, so neither does the check.
		return h, nil
	}
	base := NewBaseMiddleware(gw, spec, nil, logger)
	var middlewares []TykMiddleware
	if auth.BasicAuth.Enabled {
		middlewares = append(middlewares, getUpstreamBasicAuthMw(base))
	}
	if auth.OAuth.Enabled {
		middlewares = append(middlewares, getUpstreamOAuthMw(base))
	}
	for _, mw := range middlewares {
		if mw == nil || !mw.EnabledForSpec() {
			continue
		}
		if err, _ := mw.ProcessRequest(nil, req, nil); err != nil {
			return nil, fmt.Errorf("upstream authentication: %w", err)
		}
	}
	if provider := core.GetUpstreamAuth(req); provider != nil {
		provider.Fill(&http.Request{Header: h})
	}
	return h, nil
}

// remoteMCPCatalogueRoundTripper sends catalogue requests the way
// WrappedServeHTTP sends proxied ones: on an h2c-capable transport each
// request is marked with its final scheme, and an h2c:// URL is sent as
// http:// over HTTP/2 cleartext.
type remoteMCPCatalogueRoundTripper struct {
	rt *TykRoundTripper
}

func (c remoteMCPCatalogueRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if c.rt.h2ctransport == nil && r.URL.Scheme != "h2c" {
		return c.rt.RoundTrip(r)
	}
	out := r.Clone(r.Context())
	if c.rt.h2ctransport != nil {
		markFinalScheme(out)
	}
	if out.URL.Scheme == "h2c" {
		out.URL.Scheme = "http"
	}
	return c.rt.RoundTrip(out)
}
