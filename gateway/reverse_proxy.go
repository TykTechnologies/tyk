// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Fork of Go's net/http/httputil/reverseproxy.go with multiple changes,
// including:
//
// * caching
// * load balancing
// * service discovery

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/TykTechnologies/tyk/user"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	cache "github.com/pmylund/go-cache"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

const defaultUserAgent = "Tyk/" + VERSION

var ServiceCache *cache.Cache
var sdMu sync.RWMutex

func urlFromService(spec *APISpec) (*apidef.HostList, error) {

	doCacheRefresh := func() (*apidef.HostList, error) {
		log.Debug("--> Refreshing")
		spec.ServiceRefreshInProgress = true
		defer func() { spec.ServiceRefreshInProgress = false }()
		sd := ServiceDiscovery{}
		sd.Init(&spec.Proxy.ServiceDiscovery)
		data, err := sd.Target(spec.Proxy.ServiceDiscovery.QueryEndpoint)
		if err != nil {
			return nil, err
		}
		sdMu.Lock()
		spec.HasRun = true
		sdMu.Unlock()
		// Set the cached value
		if data.Len() == 0 {
			log.Warning("[PROXY][SD] Service Discovery returned empty host list! Returning last good set.")

			if spec.LastGoodHostList == nil {
				log.Warning("[PROXY][SD] Last good host list is nil, returning empty set.")
				spec.LastGoodHostList = apidef.NewHostList()
			}

			return spec.LastGoodHostList, nil
		}

		ServiceCache.Set(spec.APIID, data, cache.DefaultExpiration)
		// Stash it too
		spec.LastGoodHostList = data
		return data, nil
	}
	sdMu.RLock()
	hasRun := spec.HasRun
	sdMu.RUnlock()
	// First time? Refresh the cache and return that
	if !hasRun {
		log.Debug("First run! Setting cache")
		return doCacheRefresh()
	}

	// Not first run - check the cache
	cachedServiceData, found := ServiceCache.Get(spec.APIID)
	if !found {
		if spec.ServiceRefreshInProgress {
			// Are we already refreshing the cache? skip and return last good conf
			log.Debug("Cache expired! But service refresh in progress")
			return spec.LastGoodHostList, nil
		}
		// Refresh the spec
		log.Debug("Cache expired! Refreshing...")
		return doCacheRefresh()
	}

	log.Debug("Returning from cache.")
	return cachedServiceData.(*apidef.HostList), nil
}

// httpScheme matches http://* and https://*, case insensitive
var httpScheme = regexp.MustCompile(`^(?i)https?://`)

func EnsureTransport(host, protocol string) string {
	if protocol == "" {
		for _, v := range []string{"http://", "https://"} {
			if strings.HasPrefix(host, v) {
				return host
			}
		}
		return "http://" + host
	}
	prefix := protocol + "://"
	if strings.HasPrefix(host, prefix) {
		return host
	}
	return prefix + host
}

func nextTarget(targetData *apidef.HostList, spec *APISpec) (string, error) {
	if spec.Proxy.EnableLoadBalancing {
		log.Debug("[PROXY] [LOAD BALANCING] Load balancer enabled, getting upstream target")
		// Use a HostList
		startPos := spec.RoundRobin.WithLen(targetData.Len())
		pos := startPos
		for {
			gotHost, err := targetData.GetIndex(pos)
			if err != nil {
				return "", err
			}

			host := EnsureTransport(gotHost, spec.Protocol)

			if !spec.Proxy.CheckHostAgainstUptimeTests {
				return host, nil // we don't care if it's up
			}
			if !GlobalHostChecker.HostDown(host) {
				return host, nil // we do care and it's up
			}
			// if the host is down, keep trying all the rest
			// in order from where we started.
			if pos = (pos + 1) % targetData.Len(); pos == startPos {
				return "", fmt.Errorf("all hosts are down, uptime tests are failing")
			}
		}

	}
	// Use standard target - might still be service data
	log.Debug("TARGET DATA:", targetData)

	gotHost, err := targetData.GetIndex(0)
	if err != nil {
		return "", err
	}
	return EnsureTransport(gotHost, spec.Protocol), nil
}

var (
	onceStartAllHostsDown sync.Once

	allHostsDownURL string
)

// TykNewSingleHostReverseProxy returns a new ReverseProxy that rewrites
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir. This version modifies the
// stdlib version by also setting the host to the target, this allows
// us to work with heroku and other such providers
func TykNewSingleHostReverseProxy(target *url.URL, spec *APISpec) *ReverseProxy {
	onceStartAllHostsDown.Do(func() {
		handler := func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "all hosts are down", http.StatusServiceUnavailable)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		server := &http.Server{
			Handler:        http.HandlerFunc(handler),
			ReadTimeout:    1 * time.Second,
			WriteTimeout:   1 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		allHostsDownURL = "http://" + listener.Addr().String()
		go func() {
			panic(server.Serve(listener))
		}()
	})
	if spec.Proxy.ServiceDiscovery.UseDiscoveryService {
		log.Debug("[PROXY] Service discovery enabled")
		if ServiceCache == nil {
			log.Debug("[PROXY] Service cache initialising")
			expiry := 120
			if spec.Proxy.ServiceDiscovery.CacheTimeout > 0 {
				expiry = int(spec.Proxy.ServiceDiscovery.CacheTimeout)
			} else if spec.GlobalConfig.ServiceDiscovery.DefaultCacheTimeout > 0 {
				expiry = spec.GlobalConfig.ServiceDiscovery.DefaultCacheTimeout
			}
			ServiceCache = cache.New(time.Duration(expiry)*time.Second, 15*time.Second)
		}
	}

	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		hostList := spec.Proxy.StructuredTargetList
		switch {
		case spec.Proxy.ServiceDiscovery.UseDiscoveryService:
			var err error
			hostList, err = urlFromService(spec)
			if err != nil {
				log.Error("[PROXY] [SERVICE DISCOVERY] Failed target lookup: ", err)
				break
			}
			fallthrough // implies load balancing, with replaced host list
		case spec.Proxy.EnableLoadBalancing:
			host, err := nextTarget(hostList, spec)
			if err != nil {
				log.Error("[PROXY] [LOAD BALANCING] ", err)
				host = allHostsDownURL
			}
			lbRemote, err := url.Parse(host)
			if err != nil {
				log.Error("[PROXY] [LOAD BALANCING] Couldn't parse target URL:", err)
			} else {
				// Only replace target if everything is OK
				target = lbRemote
				targetQuery = target.RawQuery
			}
		}

		targetToUse := target

		if spec.URLRewriteEnabled && req.Context().Value(ctx.RetainHost) == true {
			log.Debug("Detected host rewrite, overriding target")
			tmpTarget, err := url.Parse(req.URL.String())
			if err != nil {
				log.Error("Failed to parse URL! Err: ", err)
			} else {
				// Specifically override with a URL rewrite
				targetToUse = tmpTarget
			}
		}

		// No override, and no load balancing? Use the existing target

		// if this is false, there was an url rewrite, thus we
		// don't want to do anything to the path - req.URL is
		// already final.
		if targetToUse == target {
			req.URL.Scheme = targetToUse.Scheme
			req.URL.Host = targetToUse.Host
			req.URL.Path = singleJoiningSlash(targetToUse.Path, req.URL.Path, spec.Proxy.DisableStripSlash)
			if req.URL.RawPath != "" {
				req.URL.RawPath = singleJoiningSlash(targetToUse.Path, req.URL.RawPath, spec.Proxy.DisableStripSlash)
			}
		}
		if !spec.Proxy.PreserveHostHeader {
			req.Host = targetToUse.Host
		}
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header[headers.UserAgent]; !ok {
			// Set Tyk's own default user agent. Without
			// this line, we would get the net/http default.
			req.Header.Set(headers.UserAgent, defaultUserAgent)
		}

		if spec.GlobalConfig.HttpServerOptions.SkipTargetPathEscaping {
			// force RequestURI to skip escaping if API's proxy is set for this
			// if we set opaque here it will force URL.RequestURI to skip escaping
			if req.URL.RawPath != "" {
				req.URL.Opaque = req.URL.RawPath
			}
		} else if req.URL.RawPath == req.URL.Path {
			// this should force URL to do escaping
			req.URL.RawPath = ""
		}
	}

	proxy := &ReverseProxy{
		Director:      director,
		TykAPISpec:    spec,
		FlushInterval: time.Duration(spec.GlobalConfig.HttpServerOptions.FlushInterval) * time.Millisecond,
	}
	proxy.ErrorHandler.BaseMiddleware = BaseMiddleware{Spec: spec, Proxy: proxy}
	return proxy
}

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
type ReverseProxy struct {
	// Director must be a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	Director func(*http.Request)

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// TLSClientConfig specifies the TLS configuration to use for 'wss'.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	TykAPISpec   *APISpec
	ErrorHandler ErrorHandler
}

func defaultTransport(dialerTimeout float64) *http.Transport {
	timeout := 30.0
	if dialerTimeout > 0 {
		log.Debug("Setting timeout for outbound request to: ", dialerTimeout)
		timeout = dialerTimeout
	}

	dialer := &net.Dialer{
		Timeout:   time.Duration(float64(timeout) * float64(time.Second)),
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	dialContextFunc := dialer.DialContext
	if dnsCacheManager.IsCacheEnabled() {
		dialContextFunc = dnsCacheManager.WrapDialer(dialer)
	}

	return &http.Transport{
		DialContext:           dialContextFunc,
		MaxIdleConns:          config.Global().MaxIdleConns,
		MaxIdleConnsPerHost:   config.Global().MaxIdleConnsPerHost, // default is 100
		ResponseHeaderTimeout: time.Duration(dialerTimeout) * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}
}

func singleJoiningSlash(a, b string, disableStripSlash bool) string {
	if disableStripSlash && len(b) == 0 {
		return a
	}
	a = strings.TrimRight(a, "/")
	b = strings.TrimLeft(b, "/")
	if len(b) > 0 {
		return a + "/" + b
	}
	return a
}

func copyHeader(dst, src http.Header) {
	if val := dst.Get(http.CanonicalHeaderKey("Access-Control-Allow-Origin")); len(val) > 0 {
		src.Del("Access-Control-Allow-Origin")
	}

	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) *http.Response {
	resp := p.WrappedServeHTTP(rw, req, recordDetail(req, config.Global()))

	// make response body to be nopCloser and re-readable before serve it through chain of middlewares
	nopCloseResponseBody(resp)

	return resp
}

func (p *ReverseProxy) ServeHTTPForCache(rw http.ResponseWriter, req *http.Request) *http.Response {
	resp := p.WrappedServeHTTP(rw, req, true)

	nopCloseResponseBody(resp)

	return resp
}

func (p *ReverseProxy) CheckHardTimeoutEnforced(spec *APISpec, req *http.Request) (bool, float64) {
	if !spec.EnforcedTimeoutEnabled {
		return false, spec.GlobalConfig.ProxyDefaultTimeout
	}

	_, versionPaths, _, _ := spec.Version(req)
	found, meta := spec.CheckSpecMatchesStatus(req, versionPaths, HardTimeout)
	if found {
		intMeta := meta.(*int)
		log.Debug("HARD TIMEOUT ENFORCED: ", *intMeta)
		return true, float64(*intMeta)
	}

	return false, spec.GlobalConfig.ProxyDefaultTimeout
}

func (p *ReverseProxy) CheckHeaderInRemoveList(hdr string, spec *APISpec, req *http.Request) bool {
	vInfo, versionPaths, _, _ := spec.Version(req)
	for _, gdKey := range vInfo.GlobalHeadersRemove {
		if strings.ToLower(gdKey) == strings.ToLower(hdr) {
			return true
		}
	}

	// Check path config
	if found, meta := spec.CheckSpecMatchesStatus(req, versionPaths, HeaderInjected); found {
		hmeta := meta.(*apidef.HeaderInjectionMeta)
		for _, gdKey := range hmeta.DeleteHeaders {
			if strings.ToLower(gdKey) == strings.ToLower(hdr) {
				return true
			}
		}
	}

	return false
}

func (p *ReverseProxy) CheckCircuitBreakerEnforced(spec *APISpec, req *http.Request) (bool, *ExtendedCircuitBreakerMeta) {
	if !spec.CircuitBreakerEnabled {
		return false, nil
	}

	_, versionPaths, _, _ := spec.Version(req)
	found, meta := spec.CheckSpecMatchesStatus(req, versionPaths, CircuitBreaker)
	if found {
		exMeta := meta.(*ExtendedCircuitBreakerMeta)
		log.Debug("CB Enforced for path: ", *exMeta)
		return true, exMeta
	}

	return false, nil
}

func proxyFromAPI(api *APISpec) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if api != nil && api.Proxy.Transport.ProxyURL != "" {
			return url.Parse(api.Proxy.Transport.ProxyURL)
		}
		return http.ProxyFromEnvironment(req)
	}
}

func tlsClientConfig(s *APISpec) *tls.Config {
	config := &tls.Config{}

	if s.GlobalConfig.ProxySSLInsecureSkipVerify {
		config.InsecureSkipVerify = true
	}

	if s.Proxy.Transport.SSLInsecureSkipVerify {
		config.InsecureSkipVerify = true
	}

	if s.GlobalConfig.ProxySSLMinVersion > 0 {
		config.MinVersion = s.GlobalConfig.ProxySSLMinVersion
	}

	if s.Proxy.Transport.SSLMinVersion > 0 {
		config.MinVersion = s.Proxy.Transport.SSLMinVersion
	}

	if len(s.GlobalConfig.ProxySSLCipherSuites) > 0 {
		config.CipherSuites = getCipherAliases(s.GlobalConfig.ProxySSLCipherSuites)
	}

	if len(s.Proxy.Transport.SSLCipherSuites) > 0 {
		config.CipherSuites = getCipherAliases(s.Proxy.Transport.SSLCipherSuites)
	}

	if !s.GlobalConfig.ProxySSLDisableRenegotiation {
		config.Renegotiation = tls.RenegotiateFreelyAsClient
	}

	return config
}

func httpTransport(timeOut float64, rw http.ResponseWriter, req *http.Request, p *ReverseProxy) http.RoundTripper {
	transport := defaultTransport(timeOut) // modifies a newly created transport
	transport.TLSClientConfig = &tls.Config{}
	transport.Proxy = proxyFromAPI(p.TykAPISpec)

	if config.Global().ProxySSLInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	if p.TykAPISpec.Proxy.Transport.SSLInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	// When request routed through the proxy `DialTLS` is not used, and only VerifyPeerCertificate is supported
	// The reason behind two separate checks is that `DialTLS` supports specifying public keys per hostname, and `VerifyPeerCertificate` only global ones, e.g. `*`
	if proxyURL, _ := transport.Proxy(req); proxyURL != nil {
		transport.TLSClientConfig.VerifyPeerCertificate = verifyPeerCertificatePinnedCheck(p.TykAPISpec, transport.TLSClientConfig)
	} else {
		transport.DialTLS = dialTLSPinnedCheck(p.TykAPISpec, transport.TLSClientConfig)
	}

	if p.TykAPISpec.GlobalConfig.ProxySSLMinVersion > 0 {
		transport.TLSClientConfig.MinVersion = p.TykAPISpec.GlobalConfig.ProxySSLMinVersion
	}

	if p.TykAPISpec.Proxy.Transport.SSLMinVersion > 0 {
		transport.TLSClientConfig.MinVersion = p.TykAPISpec.Proxy.Transport.SSLMinVersion
	}

	if len(p.TykAPISpec.GlobalConfig.ProxySSLCipherSuites) > 0 {
		transport.TLSClientConfig.CipherSuites = getCipherAliases(p.TykAPISpec.GlobalConfig.ProxySSLCipherSuites)
	}

	if len(p.TykAPISpec.Proxy.Transport.SSLCipherSuites) > 0 {
		transport.TLSClientConfig.CipherSuites = getCipherAliases(p.TykAPISpec.Proxy.Transport.SSLCipherSuites)
	}

	if !config.Global().ProxySSLDisableRenegotiation {
		transport.TLSClientConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	}

	transport.DisableKeepAlives = p.TykAPISpec.GlobalConfig.ProxyCloseConnections

	if IsWebsocket(req) {
		wsTransport := &WSDialer{transport, rw, p.TLSClientConfig}
		return wsTransport
	}

	if config.Global().ProxyEnableHttp2 {
		http2.ConfigureTransport(transport)
	}

	return transport
}

func (p *ReverseProxy) WrappedServeHTTP(rw http.ResponseWriter, req *http.Request, withCache bool) *http.Response {
	if trace.IsEnabled() {
		span, ctx := trace.Span(req.Context(), req.URL.Path)
		defer span.Finish()
		ext.SpanKindRPCClient.Set(span)
		req = req.WithContext(ctx)
	}
	outReqIsWebsocket := IsWebsocket(req)
	var roundTripper http.RoundTripper

	p.TykAPISpec.Lock()
	if !outReqIsWebsocket { // check if it is a regular HTTP request
		// create HTTP transport
		createTransport := p.TykAPISpec.HTTPTransport == nil

		// Check if timeouts are set for this endpoint
		if !createTransport && config.Global().MaxConnTime != 0 {
			createTransport = time.Since(p.TykAPISpec.HTTPTransportCreated) > time.Duration(config.Global().MaxConnTime)*time.Second
		}

		if createTransport {
			_, timeout := p.CheckHardTimeoutEnforced(p.TykAPISpec, req)
			p.TykAPISpec.HTTPTransport = httpTransport(timeout, rw, req, p)
			p.TykAPISpec.HTTPTransportCreated = time.Now()
		}

		roundTripper = p.TykAPISpec.HTTPTransport
	} else { // this is NEW WS-connection upgrade request
		// create WS transport
		createTransport := p.TykAPISpec.WSTransport == nil

		// Check if timeouts are set for this endpoint
		if !createTransport && config.Global().MaxConnTime != 0 {
			createTransport = time.Since(p.TykAPISpec.WSTransportCreated) > time.Duration(config.Global().MaxConnTime)*time.Second
		}

		if createTransport {
			_, timeout := p.CheckHardTimeoutEnforced(p.TykAPISpec, req)
			p.TykAPISpec.WSTransport = httpTransport(timeout, rw, req, p)
			p.TykAPISpec.WSTransportCreated = time.Now()
		}

		// overwrite transport's ResponseWriter from previous upgrade request
		// as it was already hijacked and now is being used for other connection
		p.TykAPISpec.WSTransport.(*WSDialer).RW = rw

		roundTripper = p.TykAPISpec.WSTransport
	}
	p.TykAPISpec.Unlock()

	reqCtx := req.Context()
	if cn, ok := rw.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithCancel(reqCtx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-reqCtx.Done():
			}
		}()
	}

	// Do this before we make a shallow copy
	session := ctxGetSession(req)

	outreq := new(http.Request)
	logreq := new(http.Request)

	*outreq = *req // includes shallow copies of maps, but okay
	*logreq = *req
	// remove context data from the copies
	setContext(outreq, context.Background())
	setContext(logreq, context.Background())

	log.Debug("UPSTREAM REQUEST URL: ", req.URL)

	// We need to double set the context for the outbound request to reprocess the target
	if p.TykAPISpec.URLRewriteEnabled && req.Context().Value(ctx.RetainHost) == true {
		log.Debug("Detected host rewrite, notifying director")
		setCtxValue(outreq, ctx.RetainHost, true)
	}

	if req.ContentLength == 0 {
		outreq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}
	outreq = outreq.WithContext(reqCtx)

	outreq.Header = cloneHeader(req.Header)
	if trace.IsEnabled() {
		span := opentracing.SpanFromContext(req.Context())
		trace.Inject(p.TykAPISpec.Name, span, outreq.Header)
	}
	p.Director(outreq)
	outreq.Close = false

	log.Debug("Outbound Request: ", outreq.URL.String())

	// Do not modify outbound request headers if they are WS
	if !outReqIsWebsocket {
		// Remove hop-by-hop headers listed in the "Connection" header.
		// See RFC 2616, section 14.10.
		if c := outreq.Header.Get("Connection"); c != "" {
			for _, f := range strings.Split(c, ",") {
				if f = strings.TrimSpace(f); f != "" {
					outreq.Header.Del(f)
				}
			}
		}
		// Remove other hop-by-hop headers to the backend. Especially
		// important is "Connection" because we want a persistent
		// connection, regardless of what the client sent to us.
		for _, h := range hopHeaders {
			hv := outreq.Header.Get(h)
			if hv == "" {
				continue
			}
			if h == "Te" && hv == "trailers" {
				continue
			}
			outreq.Header.Del(h)
			logreq.Header.Del(h)
		}
	}

	addrs := requestIPHops(req)
	if !p.CheckHeaderInRemoveList(headers.XForwardFor, p.TykAPISpec, req) {
		outreq.Header.Set(headers.XForwardFor, addrs)
	}

	// Circuit breaker
	breakerEnforced, breakerConf := p.CheckCircuitBreakerEnforced(p.TykAPISpec, req)

	// set up TLS certificates for upstream if needed
	var tlsCertificates []tls.Certificate
	if cert := getUpstreamCertificate(outreq.Host, p.TykAPISpec); cert != nil {
		tlsCertificates = []tls.Certificate{*cert}
	}

	p.TykAPISpec.Lock()
	if outReqIsWebsocket {
		roundTripper.(*WSDialer).TLSClientConfig.Certificates = tlsCertificates
	} else {
		roundTripper.(*http.Transport).TLSClientConfig.Certificates = tlsCertificates
	}
	p.TykAPISpec.Unlock()

	// do request round trip
	var res *http.Response
	var err error
	if breakerEnforced {
		if !breakerConf.CB.Ready() {
			log.Debug("ON REQUEST: Circuit Breaker is in OPEN state")
			p.ErrorHandler.HandleError(rw, logreq, "Service temporarily unavailable.", 503, true)
			return nil
		}
		log.Debug("ON REQUEST: Circuit Breaker is in CLOSED or HALF-OPEN state")
		res, err = roundTripper.RoundTrip(outreq)
		if err != nil || res.StatusCode == http.StatusInternalServerError {
			breakerConf.CB.Fail()
		} else {
			breakerConf.CB.Success()
		}
	} else {
		res, err = roundTripper.RoundTrip(outreq)
	}

	if err != nil {

		token := ctxGetAuthToken(req)

		var alias string
		if session != nil {
			alias = session.Alias
		}

		log.WithFields(logrus.Fields{
			"prefix":      "proxy",
			"user_ip":     addrs,
			"server_name": outreq.Host,
			"user_id":     obfuscateKey(token),
			"user_name":   alias,
			"org_id":      p.TykAPISpec.OrgID,
			"api_id":      p.TykAPISpec.APIID,
		}).Error("http: proxy error: ", err)

		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			p.ErrorHandler.HandleError(rw, logreq, "Upstream service reached hard timeout.", http.StatusGatewayTimeout, true)

			if p.TykAPISpec.Proxy.ServiceDiscovery.UseDiscoveryService {
				if ServiceCache != nil {
					log.Debug("[PROXY] [SERVICE DISCOVERY] Upstream host failed, refreshing host list")
					ServiceCache.Delete(p.TykAPISpec.APIID)
				}
			}
			return nil
		}

		if strings.Contains(err.Error(), "context canceled") {
			p.ErrorHandler.HandleError(rw, logreq, "Client closed request", 499, true)
			return nil
		}

		if strings.Contains(err.Error(), "no such host") {
			p.ErrorHandler.HandleError(rw, logreq, "Upstream host lookup failed", http.StatusInternalServerError, true)
			return nil
		}

		p.ErrorHandler.HandleError(rw, logreq, "There was a problem proxying the request", http.StatusInternalServerError, true)
		return nil

	}

	if IsWebsocket(req) {
		return nil
	}

	ses := new(user.SessionState)
	if session != nil {
		ses = session
	}

	// Middleware chain handling here - very simple, but should do
	// the trick. Chain can be empty, in which case this is a no-op.
	// abortRequest is set to true when a response hook fails
	// For reference see "HandleError" in coprocess.go
	abortRequest, err := handleResponseChain(p.TykAPISpec.ResponseChain, rw, res, req, ses)
	if abortRequest {
		return nil
	}

	if err != nil {
		log.Error("Response chain failed! ", err)
	}

	inres := new(http.Response)
	if withCache {
		*inres = *res // includes shallow copies of maps, but okay

		defer res.Body.Close()

		// Buffer body data
		var bodyBuffer bytes.Buffer
		bodyBuffer2 := new(bytes.Buffer)

		p.CopyResponse(&bodyBuffer, res.Body)
		*bodyBuffer2 = bodyBuffer

		// Create new ReadClosers so we can split output
		res.Body = ioutil.NopCloser(&bodyBuffer)
		inres.Body = ioutil.NopCloser(bodyBuffer2)
	}

	// We should at least copy the status code in
	inres.StatusCode = res.StatusCode
	inres.ContentLength = res.ContentLength
	p.HandleResponse(rw, res, ses)
	return inres
}

func (p *ReverseProxy) HandleResponse(rw http.ResponseWriter, res *http.Response, ses *user.SessionState) error {

	// Remove hop-by-hop headers listed in the
	// "Connection" header of the response.
	if c := res.Header.Get(headers.Connection); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				res.Header.Del(f)
			}
		}
	}

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}
	defer res.Body.Close()

	// Close connections
	if config.Global().CloseConnections {
		res.Header.Set(headers.Connection, "close")
	}

	// Add resource headers
	if ses != nil {
		// We have found a session, lets report back
		quotaMax, quotaRemaining, _, quotaRenews := ses.GetQuotaLimitByAPIID(p.TykAPISpec.APIID)
		res.Header.Set(headers.XRateLimitLimit, strconv.Itoa(int(quotaMax)))
		res.Header.Set(headers.XRateLimitRemaining, strconv.Itoa(int(quotaRemaining)))
		res.Header.Set(headers.XRateLimitReset, strconv.Itoa(int(quotaRenews)))
	}

	copyHeader(rw.Header(), res.Header)

	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	p.CopyResponse(rw, res.Body)

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer)
		return nil
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
	return nil
}

func (p *ReverseProxy) CopyResponse(dst io.Writer, src io.Reader) {
	if p.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: p.FlushInterval,
				done:    make(chan bool),
			}
			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}

	p.copyBuffer(dst, src, nil)
}

func (p *ReverseProxy) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			log.WithFields(logrus.Fields{
				"prefix": "proxy",
				"org_id": p.TykAPISpec.OrgID,
				"api_id": p.TykAPISpec.APIID,
			}).Error("http: proxy error during body copy: ", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			return written, rerr
		}
	}
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration

	mu   sync.Mutex // protects Write + Flush
	done chan bool
}

func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dst.Write(p)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.mu.Lock()
			m.dst.Flush()
			m.mu.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() { m.done <- true }

func requestIPHops(r *http.Request) string {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	// If we aren't the first proxy retain prior
	// X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	if prior, ok := r.Header["X-Forwarded-For"]; ok {
		clientIP = strings.Join(prior, ", ") + ", " + clientIP
	}
	return clientIP
}

// nopCloser is just like ioutil's, but here to let us re-read the same
// buffer inside by moving position to the start every time we done with reading
type nopCloser struct {
	io.ReadSeeker
}

// Read just a wrapper around real Read which also moves position to the start if we get EOF
// to have it ready for next read-cycle
func (n nopCloser) Read(p []byte) (int, error) {
	num, err := n.ReadSeeker.Read(p)
	if err == io.EOF { // move to start to have it ready for next read cycle
		n.Seek(0, io.SeekStart)
	}
	return num, err
}

// Close is a no-op Close
func (n nopCloser) Close() error {
	return nil
}

func copyBody(body io.ReadCloser) io.ReadCloser {
	// check if body was already read and converted into our nopCloser
	if nc, ok := body.(nopCloser); ok {
		// seek to the beginning to have it ready for next read
		nc.Seek(0, io.SeekStart)
		return body
	}

	// body is http's io.ReadCloser - let's close it after we read data
	defer body.Close()

	// body is http's io.ReadCloser - read it up until EOF
	var bodyRead bytes.Buffer
	io.Copy(&bodyRead, body)

	// use seek-able reader for further body usage
	reusableBody := bytes.NewReader(bodyRead.Bytes())

	return nopCloser{reusableBody}
}

func copyRequest(r *http.Request) *http.Request {
	if r.Body != nil {
		r.Body = copyBody(r.Body)
	}
	return r
}

func copyResponse(r *http.Response) *http.Response {
	if r.Body != nil {
		r.Body = copyBody(r.Body)
	}
	return r
}

func nopCloseRequestBody(r *http.Request) {
	if r == nil {
		return
	}

	copyRequest(r)
}

func nopCloseResponseBody(r *http.Response) {
	if r == nil {
		return
	}

	copyResponse(r)
}
