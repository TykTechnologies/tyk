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
	"crypto/x509"
	"errors"
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

	"github.com/gorilla/websocket"
	"github.com/jensneuse/abstractlogger"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	gqlhttp "github.com/TykTechnologies/graphql-go-tools/pkg/http"
	"github.com/TykTechnologies/graphql-go-tools/pkg/subscription"

	"github.com/akutz/memconn"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/pmylund/go-cache"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/TykTechnologies/tyk/user"
)

var defaultUserAgent = "Tyk/" + VERSION

var corsHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Allow-Credentials",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers"}

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
	host = strings.TrimSpace(host)
	protocol = strings.TrimSpace(protocol)
	u, err := url.Parse(host)
	if err != nil {
		return host
	}
	switch u.Scheme {
	case "":
		if protocol == "" {
			protocol = "http"
		}
		u.Scheme = protocol
	case "h2c":
		u.Scheme = "http"
	}
	return u.String()
}

func (gw *Gateway) nextTarget(targetData *apidef.HostList, spec *APISpec) (string, error) {
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
			// As checked by HostCheckerManager.AmIPolling
			if gw.GlobalHostChecker.store == nil {
				return host, nil
			}
			if !gw.GlobalHostChecker.HostDown(host) {
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
func (gw *Gateway) TykNewSingleHostReverseProxy(target *url.URL, spec *APISpec, logger *logrus.Entry) *ReverseProxy {
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
			host, err := gw.nextTarget(hostList, spec)
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

		switch req.URL.Scheme {
		case "ws":
			req.URL.Scheme = "http"
		case "wss":
			req.URL.Scheme = "https"
		}
	}

	if logger == nil {
		logger = logrus.NewEntry(log)
	}

	logger = logger.WithField("mw", "ReverseProxy")

	proxy := &ReverseProxy{
		Director:      director,
		TykAPISpec:    spec,
		FlushInterval: time.Duration(spec.GlobalConfig.HttpServerOptions.FlushInterval) * time.Millisecond,
		logger:        logger,
		wsUpgrader: websocket.Upgrader{
			// CheckOrigin is not needed for the upgrader as tyk already provides
			// its own middlewares for that.
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		sp: sync.Pool{
			New: func() interface{} {
				buffer := make([]byte, 32*1024)
				return &buffer
			},
		},
		Gw: gw,
	}
	proxy.ErrorHandler.BaseMiddleware = BaseMiddleware{Spec: spec, Proxy: proxy, Gw: gw}
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

	// wsUpgrader takes care of upgrading the incoming connection
	// to a websocket connection.
	wsUpgrader websocket.Upgrader

	TykAPISpec   *APISpec
	ErrorHandler ErrorHandler

	logger *logrus.Entry
	sp     sync.Pool
	Gw     *Gateway `json:"-"`
}

func (p *ReverseProxy) defaultTransport(dialerTimeout float64) *http.Transport {
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
	if p.Gw.dnsCacheManager.IsCacheEnabled() {
		dialContextFunc = p.Gw.dnsCacheManager.WrapDialer(dialer)
	}

	if p.Gw.dialCtxFn != nil {
		dialContextFunc = p.Gw.dialCtxFn
	}

	transport := &http.Transport{
		DialContext:           dialContextFunc,
		MaxIdleConns:          p.Gw.GetConfig().MaxIdleConns,
		MaxIdleConnsPerHost:   p.Gw.GetConfig().MaxIdleConnsPerHost, // default is 100
		ResponseHeaderTimeout: time.Duration(dialerTimeout) * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}

	return transport
}

func singleJoiningSlash(a, b string, disableStripSlash bool) string {
	if disableStripSlash && (len(b) == 0 || b == "/") {
		return a
	}
	a = strings.TrimRight(a, "/")
	b = strings.TrimLeft(b, "/")
	if len(b) > 0 {
		return a + "/" + b
	}
	return a
}

func removeDuplicateCORSHeader(dst, src http.Header) {
	for _, v := range corsHeaders {
		keyName := http.CanonicalHeaderKey(v)
		if val := dst.Get(keyName); val != "" {
			src.Del(keyName)
		}
	}
}

func copyHeader(dst, src http.Header, ignoreCanonical bool) {

	removeDuplicateCORSHeader(dst, src)

	for k, vv := range src {
		if ignoreCanonical {
			dst[k] = append(dst[k], vv...)
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func addCustomHeader(h http.Header, key string, value []string, ignoreCanonical bool) {
	if ignoreCanonical {
		h[key] = append(h[key], value...)
	} else {
		for _, v := range value {
			h.Add(key, v)
		}
	}

}

func setCustomHeader(h http.Header, key string, value string, ignoreCanonical bool) {
	if ignoreCanonical {
		h[key] = []string{value}
	} else {
		h.Set(key, value)
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

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) ProxyResponse {
	startTime := time.Now()
	p.logger.WithField("ts", startTime.UnixNano()).Debug("Started")
	resp := p.WrappedServeHTTP(rw, req, recordDetail(req, p.TykAPISpec))

	finishTime := time.Since(startTime)
	p.logger.WithField("ns", finishTime.Nanoseconds()).Debug("Finished")

	// make response body to be nopCloser and re-readable before serve it through chain of middlewares
	nopCloseResponseBody(resp.Response)

	return resp
}

func (p *ReverseProxy) ServeHTTPForCache(rw http.ResponseWriter, req *http.Request) ProxyResponse {
	startTime := time.Now()
	p.logger.WithField("ts", startTime.UnixNano()).Debug("Started")

	resp := p.WrappedServeHTTP(rw, req, true)
	nopCloseResponseBody(resp.Response)
	finishTime := time.Since(startTime)
	p.logger.WithField("ns", finishTime.Nanoseconds()).Debug("Finished")

	return resp
}

func (p *ReverseProxy) CheckHardTimeoutEnforced(spec *APISpec, req *http.Request) (bool, float64) {
	if !spec.EnforcedTimeoutEnabled {
		return false, spec.GlobalConfig.ProxyDefaultTimeout
	}

	vInfo, _ := spec.Version(req)
	versionPaths := spec.RxPaths[vInfo.Name]
	found, meta := spec.CheckSpecMatchesStatus(req, versionPaths, HardTimeout)
	if found {
		intMeta := meta.(*int)
		p.logger.Debug("HARD TIMEOUT ENFORCED: ", *intMeta)
		return true, float64(*intMeta)
	}

	return false, spec.GlobalConfig.ProxyDefaultTimeout
}

func (p *ReverseProxy) CheckHeaderInRemoveList(hdr string, spec *APISpec, req *http.Request) bool {
	vInfo, _ := spec.Version(req)
	versionPaths := spec.RxPaths[vInfo.Name]
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

	versionInfo, _ := spec.Version(req)
	versionPaths := spec.RxPaths[versionInfo.Name]
	found, meta := spec.CheckSpecMatchesStatus(req, versionPaths, CircuitBreaker)
	if found {
		exMeta := meta.(*ExtendedCircuitBreakerMeta)
		p.logger.Debug("CB Enforced for path: ", *exMeta)
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

	if s.GlobalConfig.ProxySSLMaxVersion > 0 {
		config.MaxVersion = s.GlobalConfig.ProxySSLMaxVersion
	}

	if s.Proxy.Transport.SSLMaxVersion > 0 {
		config.MaxVersion = s.Proxy.Transport.SSLMaxVersion
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

func (p *ReverseProxy) httpTransport(timeOut float64, rw http.ResponseWriter, req *http.Request, outReq *http.Request) *TykRoundTripper {
	p.logger.Debug("Creating new transport")
	transport := p.defaultTransport(timeOut) // modifies a newly created transport
	transport.TLSClientConfig = &tls.Config{}
	transport.Proxy = proxyFromAPI(p.TykAPISpec)

	if p.Gw.GetConfig().ProxySSLInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	if p.TykAPISpec.Proxy.Transport.SSLInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	// When request routed through the proxy `DialTLS` is not used, and only VerifyPeerCertificate is supported
	// The reason behind two separate checks is that `DialTLS` supports specifying public keys per hostname, and `VerifyPeerCertificate` only global ones, e.g. `*`
	if proxyURL, _ := transport.Proxy(req); proxyURL != nil {
		p.logger.Debug("Detected proxy: " + proxyURL.String())
		transport.TLSClientConfig.VerifyPeerCertificate = p.Gw.verifyPeerCertificatePinnedCheck(p.TykAPISpec, transport.TLSClientConfig)

		if transport.TLSClientConfig.VerifyPeerCertificate != nil {
			p.logger.Debug("Certificate pinning check is enabled")
		}
	} else {
		transport.DialTLS = p.Gw.customDialTLSCheck(p.TykAPISpec, transport.TLSClientConfig)
	}

	if p.TykAPISpec.GlobalConfig.ProxySSLMinVersion > 0 {
		transport.TLSClientConfig.MinVersion = p.TykAPISpec.GlobalConfig.ProxySSLMinVersion
	}

	if p.TykAPISpec.Proxy.Transport.SSLMinVersion > 0 {
		transport.TLSClientConfig.MinVersion = p.TykAPISpec.Proxy.Transport.SSLMinVersion
	}

	if p.TykAPISpec.GlobalConfig.ProxySSLMaxVersion > 0 {
		transport.TLSClientConfig.MaxVersion = p.TykAPISpec.GlobalConfig.ProxySSLMaxVersion
	}

	if p.TykAPISpec.Proxy.Transport.SSLMaxVersion > 0 {
		transport.TLSClientConfig.MaxVersion = p.TykAPISpec.Proxy.Transport.SSLMaxVersion
	}

	if len(p.TykAPISpec.GlobalConfig.ProxySSLCipherSuites) > 0 {
		transport.TLSClientConfig.CipherSuites = getCipherAliases(p.TykAPISpec.GlobalConfig.ProxySSLCipherSuites)
	}

	if len(p.TykAPISpec.Proxy.Transport.SSLCipherSuites) > 0 {
		transport.TLSClientConfig.CipherSuites = getCipherAliases(p.TykAPISpec.Proxy.Transport.SSLCipherSuites)
	}

	if !p.Gw.GetConfig().ProxySSLDisableRenegotiation {
		transport.TLSClientConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	}

	transport.DisableKeepAlives = p.TykAPISpec.GlobalConfig.ProxyCloseConnections

	if p.Gw.GetConfig().ProxyEnableHttp2 {
		http2.ConfigureTransport(transport)
	}

	p.logger.Debug("Out request url: ", outReq.URL.String())

	if outReq.URL.Scheme == "h2c" {
		p.logger.Info("Enabling h2c mode")
		h2t := &http2.Transport{
			// kind of a hack, but for plaintext/H2C requests, pretend to dial TLS
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			AllowHTTP: true,
		}
		return &TykRoundTripper{transport, h2t, p.logger, p.Gw}
	}

	return &TykRoundTripper{transport, nil, p.logger, p.Gw}
}

func (p *ReverseProxy) setCommonNameVerifyPeerCertificate(tlsConfig *tls.Config, hostName string) {
	tlsConfig.InsecureSkipVerify = true

	// if verifyPeerCertificate was set previously, make sure it is also executed
	prevFunc := tlsConfig.VerifyPeerCertificate
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if prevFunc != nil {
			err := prevFunc(rawCerts, verifiedChains)
			if err != nil {
				p.logger.Error("Failed to verify server certificate: " + err.Error())
				return err
			}
		}

		// followed https://github.com/golang/go/issues/21971#issuecomment-332693931
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		if !p.TykAPISpec.Proxy.Transport.SSLInsecureSkipVerify && !p.Gw.GetConfig().ProxySSLInsecureSkipVerify {
			opts := x509.VerifyOptions{
				Roots:         tlsConfig.RootCAs,
				CurrentTime:   time.Now(),
				DNSName:       "", // <- skip hostname verification
				Intermediates: x509.NewCertPool(),
			}

			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			if err != nil {
				p.logger.Error("Failed to verify server certificate: " + err.Error())
				return err
			}
		}

		return validateCommonName(hostName, certs[0])
	}
}

type TykRoundTripper struct {
	transport    *http.Transport
	h2ctransport *http2.Transport
	logger       *logrus.Entry
	Gw           *Gateway `json:"-"`
}

func (rt *TykRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {

	hasInternalHeader := r.Header.Get(apidef.TykInternalApiHeader) != ""

	if r.URL.Scheme == "tyk" || hasInternalHeader {
		if hasInternalHeader {
			r.Header.Del(apidef.TykInternalApiHeader)
		}

		handler, _, found := rt.Gw.findInternalHttpHandlerByNameOrID(r.Host)
		if !found {
			rt.logger.WithField("looping_url", "tyk://"+r.Host).Error("Couldn't detect target")
			return nil, errors.New("handler could")
		}

		rt.logger.WithField("looping_url", "tyk://"+r.Host).Debug("Executing request on internal route")

		return handleInMemoryLoop(handler, r)
	}

	if rt.h2ctransport != nil {
		return rt.h2ctransport.RoundTrip(r)
	}
	return rt.transport.RoundTrip(r)
}

const (
	checkIdleMemConnInterval = 5 * time.Minute
	maxIdleMemConnDuration   = time.Minute
	inMemNetworkName         = "in-mem-network"
	inMemNetworkType         = "memu"
)

type memConnProvider struct {
	listener net.Listener
	provider *memconn.Provider
	expireAt time.Time
}

var memConnProviders = &struct {
	mtx sync.RWMutex
	m   map[string]*memConnProvider
}{
	m: make(map[string]*memConnProvider),
}

// cleanIdleMemConnProvidersEagerly deletes idle memconn.Provider instances and
// closes the underlying listener to free resources.
func cleanIdleMemConnProvidersEagerly(pointInTime time.Time) {
	memConnProviders.mtx.Lock()
	defer memConnProviders.mtx.Unlock()

	for host, mp := range memConnProviders.m {
		if mp.expireAt.Before(pointInTime) {
			delete(memConnProviders.m, host)
			// on listener.Close http.Serve will return with error and stop goroutine
			_ = mp.listener.Close()
		}
	}
}

// cleanIdleMemConnProviders checks memconn.Provider instances periodically and
// deletes idle ones.
func cleanIdleMemConnProviders(ctx context.Context) {
	ticker := time.NewTicker(checkIdleMemConnInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanIdleMemConnProvidersEagerly(time.Now())
		}
	}
}

// getMemConnProvider return the cached memconn.Provider, if it's available in the cache.
func getMemConnProvider(addr string) (*memconn.Provider, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	memConnProviders.mtx.RLock()
	defer memConnProviders.mtx.RUnlock()

	p, ok := memConnProviders.m[host]
	if !ok {
		return nil, fmt.Errorf("no provider found for: %s", addr)
	}

	return p.provider, nil
}

// createMemConnProviderIfNeeded creates a new memconn.Provider and net.Listener
// for the given host.
func createMemConnProviderIfNeeded(handler http.Handler, r *http.Request) error {
	memConnProviders.mtx.Lock()
	defer memConnProviders.mtx.Unlock()

	p, ok := memConnProviders.m[r.Host]
	if ok {
		// Clean the providers and close its listener, if it is idle for a while.
		p.expireAt = time.Now().Add(maxIdleMemConnDuration)
		return nil
	}

	provider := &memconn.Provider{}
	// start in mem listener
	lis, err := provider.Listen(inMemNetworkType, inMemNetworkName)
	if err != nil {
		return err
	}

	// start http server with in mem listener
	// Note: do not try to use http.Server it is working only with mux
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	go func() { _ = http.Serve(lis, mux) }()

	memConnProviders.m[r.Host] = &memConnProvider{
		listener: lis,
		provider: provider,
		expireAt: time.Now().Add(maxIdleMemConnDuration),
	}
	return nil
}

// memConnClient is used to make request to internal APIs.
var memConnClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			provider, err := getMemConnProvider(addr)
			if err != nil {
				return nil, err
			}
			return provider.DialContext(ctx, inMemNetworkType, inMemNetworkName)
		},
	},
}

func handleInMemoryLoop(handler http.Handler, r *http.Request) (resp *http.Response, err error) {
	err = createMemConnProviderIfNeeded(handler, r)
	if err != nil {
		return nil, err
	}

	r.URL.Scheme = "http"
	return memConnClient.Do(r)
}

func (p *ReverseProxy) handleOutboundRequest(roundTripper *TykRoundTripper, outreq *http.Request, w http.ResponseWriter) (res *http.Response, hijacked bool, latency time.Duration, err error) {
	begin := time.Now()
	defer func() {
		latency = time.Since(begin)
	}()

	if p.TykAPISpec.GraphQL.Enabled {
		res, hijacked, err = p.handleGraphQL(roundTripper, outreq, w)
		return
	}

	res, err = p.sendRequestToUpstream(roundTripper, outreq)
	return
}

func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions
}

func (p *ReverseProxy) handleGraphQL(roundTripper *TykRoundTripper, outreq *http.Request, w http.ResponseWriter) (res *http.Response, hijacked bool, err error) {
	isWebSocketUpgrade := ctxGetGraphQLIsWebSocketUpgrade(outreq)
	needEngine := needsGraphQLExecutionEngine(p.TykAPISpec)

	switch {
	case isCORSPreflight(outreq):
		if needEngine {
			err = errors.New("options passthrough not allowed")
			return
		}
	case isWebSocketUpgrade:
		if needEngine {
			return p.handleGraphQLEngineWebsocketUpgrade(roundTripper, outreq, w)
		}
	default:
		gqlRequest := ctxGetGraphQLRequest(outreq)
		if gqlRequest == nil {
			err = errors.New("graphql request is nil")
			return
		}
		gqlRequest.SetHeader(outreq.Header)

		var isIntrospection bool
		isIntrospection, err = gqlRequest.IsIntrospectionQuery()
		if err != nil {
			return
		}

		if isIntrospection {
			res, err = p.handleGraphQLIntrospection()
			return
		}
		if needEngine {
			return p.handoverRequestToGraphQLExecutionEngine(roundTripper, gqlRequest, outreq)
		}
	}

	res, err = p.sendRequestToUpstream(roundTripper, outreq)
	return
}

func (p *ReverseProxy) handleGraphQLIntrospection() (res *http.Response, err error) {
	result, err := graphql.SchemaIntrospection(p.TykAPISpec.GraphQLExecutor.Schema)
	if err != nil {
		return
	}

	res = result.GetAsHTTPResponse()
	return
}

func (p *ReverseProxy) handleGraphQLEngineWebsocketUpgrade(roundTripper *TykRoundTripper, r *http.Request, w http.ResponseWriter) (res *http.Response, hijacked bool, err error) {
	conn, err := p.wsUpgrader.Upgrade(w, r, http.Header{
		headers.SecWebSocketProtocol: {GraphQLWebSocketProtocol},
	})
	if err != nil {
		p.logger.Error("websocket upgrade for GraphQL engine failed: ", err)
		return nil, false, err
	}

	p.handoverWebSocketConnectionToGraphQLExecutionEngine(roundTripper, conn.UnderlyingConn(), r)
	return nil, true, nil
}

func (p *ReverseProxy) handoverRequestToGraphQLExecutionEngine(roundTripper *TykRoundTripper, gqlRequest *graphql.Request, outreq *http.Request) (res *http.Response, hijacked bool, err error) {
	p.TykAPISpec.GraphQLExecutor.Client.Transport = NewGraphQLEngineTransport(DetermineGraphQLEngineTransportType(p.TykAPISpec), roundTripper)

	switch p.TykAPISpec.GraphQL.Version {
	case apidef.GraphQLConfigVersionNone:
		fallthrough
	case apidef.GraphQLConfigVersion1:
		if p.TykAPISpec.GraphQLExecutor.Engine == nil {
			err = errors.New("execution engine is nil")
			return
		}

		var result *graphql.ExecutionResult
		result, err = p.TykAPISpec.GraphQLExecutor.Engine.Execute(context.Background(), gqlRequest, graphql.ExecutionOptions{ExtraArguments: gqlRequest.Variables})
		if err != nil {
			return
		}

		res = result.GetAsHTTPResponse()
		return
	case apidef.GraphQLConfigVersion2:
		if p.TykAPISpec.GraphQLExecutor.EngineV2 == nil {
			err = errors.New("execution engine is nil")
			return
		}

		isProxyOnly := isGraphQLProxyOnly(p.TykAPISpec)
		reqCtx := context.Background()
		if isProxyOnly {
			reqCtx = NewGraphQLProxyOnlyContext(context.Background(), outreq)
		}

		resultWriter := graphql.NewEngineResultWriter()
		err = p.TykAPISpec.GraphQLExecutor.EngineV2.Execute(reqCtx, gqlRequest, &resultWriter,
			graphql.WithBeforeFetchHook(p.TykAPISpec.GraphQLExecutor.HooksV2.BeforeFetchHook),
			graphql.WithAfterFetchHook(p.TykAPISpec.GraphQLExecutor.HooksV2.AfterFetchHook),
		)
		if err != nil {
			return
		}

		httpStatus := http.StatusOK
		header := make(http.Header)
		header.Set("Content-Type", "application/json")

		if isProxyOnly {
			proxyOnlyCtx := reqCtx.(*GraphQLProxyOnlyContext)
			header = proxyOnlyCtx.upstreamResponse.Header
			httpStatus = proxyOnlyCtx.upstreamResponse.StatusCode
		}

		res = resultWriter.AsHTTPResponse(httpStatus, header)
		return
	}

	return nil, false, errors.New("graphql configuration is invalid")
}

func (p *ReverseProxy) handoverWebSocketConnectionToGraphQLExecutionEngine(roundTripper *TykRoundTripper, conn net.Conn, req *http.Request) {
	p.TykAPISpec.GraphQLExecutor.Client.Transport = NewGraphQLEngineTransport(DetermineGraphQLEngineTransportType(p.TykAPISpec), roundTripper)

	absLogger := abstractlogger.NewLogrusLogger(log, absLoggerLevel(log.Level))
	done := make(chan bool)
	errChan := make(chan error)

	var executorPool subscription.ExecutorPool
	switch p.TykAPISpec.GraphQL.Version {
	case apidef.GraphQLConfigVersionNone:
		fallthrough
	case apidef.GraphQLConfigVersion1:
		if p.TykAPISpec.GraphQLExecutor.Engine == nil {
			log.Error("could not start graphql websocket handler: execution engine is nil")
			return
		}
		executorPool = subscription.NewExecutorV1Pool(p.TykAPISpec.GraphQLExecutor.Engine.NewExecutionHandler())
	case apidef.GraphQLConfigVersion2:
		if p.TykAPISpec.GraphQLExecutor.EngineV2 == nil {
			log.Error("could not start graphql websocket handler: execution engine is nil")
			return
		}
		initialRequestContext := subscription.NewInitialHttpRequestContext(req)
		executorPool = subscription.NewExecutorV2Pool(p.TykAPISpec.GraphQLExecutor.EngineV2, initialRequestContext)
	}

	go gqlhttp.HandleWebsocket(done, errChan, conn, executorPool, absLogger)
	select {
	case err := <-errChan:
		log.Error("could not start graphql websocket handler: ", err)
	case <-done:
	}
}

func (p *ReverseProxy) sendRequestToUpstream(roundTripper *TykRoundTripper, outreq *http.Request) (res *http.Response, err error) {
	return roundTripper.RoundTrip(outreq)
}

func (p *ReverseProxy) WrappedServeHTTP(rw http.ResponseWriter, req *http.Request, withCache bool) ProxyResponse {
	if trace.IsEnabled() {
		span, ctx := trace.Span(req.Context(), req.URL.Path)
		defer span.Finish()
		ext.SpanKindRPCClient.Set(span)
		req = req.WithContext(ctx)
	}
	var roundTripper *TykRoundTripper

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
	// mantain the body
	copyRequest(req)

	outreq := new(http.Request)
	logreq := new(http.Request)

	*outreq = *req // includes shallow copies of maps, but okay
	*logreq = *req
	// remove context data from the copies
	setContext(outreq, context.Background())
	setContext(logreq, context.Background())

	p.logger.Debug("Upstream request URL: ", req.URL)

	// We need to double set the context for the outbound request to reprocess the target
	if p.TykAPISpec.URLRewriteEnabled && req.Context().Value(ctx.RetainHost) == true {
		p.logger.Debug("Detected host rewrite, notifying director")
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

	p.logger.Debug("Outbound request URL: ", outreq.URL.String())

	outReqUpgrade, reqUpType := p.IsUpgrade(req)

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

	if outReqUpgrade {
		outreq.Header.Set("Connection", "Upgrade")
		logreq.Header.Set("Connection", "Upgrade")
		outreq.Header.Set("Upgrade", reqUpType)
		logreq.Header.Set("Upgrade", reqUpType)
	}

	addrs := requestIPHops(req)
	if !p.CheckHeaderInRemoveList(headers.XForwardFor, p.TykAPISpec, req) {
		outreq.Header.Set(headers.XForwardFor, addrs)
	}

	// Circuit breaker
	breakerEnforced, breakerConf := p.CheckCircuitBreakerEnforced(p.TykAPISpec, req)

	// set up TLS certificates for upstream if needed
	var tlsCertificates []tls.Certificate
	if cert := p.Gw.getUpstreamCertificate(outreq.URL.Host, p.TykAPISpec); cert != nil {
		p.logger.Debug("Found upstream mutual TLS certificate")
		tlsCertificates = []tls.Certificate{*cert}
	}

	p.TykAPISpec.Lock()

	// create HTTP transport
	createTransport := p.TykAPISpec.HTTPTransport == nil

	// Check if timeouts are set for this endpoint
	if !createTransport && p.Gw.GetConfig().MaxConnTime != 0 {
		createTransport = time.Since(p.TykAPISpec.HTTPTransportCreated) > time.Duration(p.Gw.GetConfig().MaxConnTime)*time.Second
	}

	if createTransport {
		_, timeout := p.CheckHardTimeoutEnforced(p.TykAPISpec, req)
		p.TykAPISpec.HTTPTransport = p.httpTransport(timeout, rw, req, outreq)
		p.TykAPISpec.HTTPTransportCreated = time.Now()
	}

	roundTripper = p.TykAPISpec.HTTPTransport

	if roundTripper.transport != nil {
		roundTripper.transport.TLSClientConfig.Certificates = tlsCertificates
	}
	p.TykAPISpec.Unlock()

	if outreq.URL.Scheme == "h2c" {
		outreq.URL.Scheme = "http"
	}

	if p.TykAPISpec.Proxy.Transport.SSLForceCommonNameCheck || p.Gw.GetConfig().SSLForceCommonNameCheck {
		// if proxy is enabled, add CommonName verification in verifyPeerCertificate
		// DialTLS is not executed if proxy is used
		httpTransport := roundTripper.transport

		p.logger.Debug("Using forced SSL CN check")

		if proxyURL, _ := httpTransport.Proxy(req); proxyURL != nil {
			p.logger.Debug("Detected proxy: " + proxyURL.String())
			tlsConfig := httpTransport.TLSClientConfig
			host, _, _ := net.SplitHostPort(outreq.Host)
			p.setCommonNameVerifyPeerCertificate(tlsConfig, host)
		}

	}

	// do request round trip
	var (
		res             *http.Response
		isHijacked      bool
		upstreamLatency time.Duration
		err             error
	)

	if breakerEnforced {
		if !breakerConf.CB.Ready() {
			p.logger.Debug("ON REQUEST: Circuit Breaker is in OPEN state")
			p.ErrorHandler.HandleError(rw, logreq, "Service temporarily unavailable.", 503, true)
			return ProxyResponse{}
		}
		p.logger.Debug("ON REQUEST: Circuit Breaker is in CLOSED or HALF-OPEN state")

		res, isHijacked, upstreamLatency, err = p.handleOutboundRequest(roundTripper, outreq, rw)
		if err != nil || res.StatusCode/100 == 5 {
			breakerConf.CB.Fail()
		} else {
			breakerConf.CB.Success()
		}
	} else {
		res, isHijacked, upstreamLatency, err = p.handleOutboundRequest(roundTripper, outreq, rw)
	}

	if err != nil {

		token := ctxGetAuthToken(req)

		var alias string
		if session != nil {
			alias = session.Alias
		}

		p.logger.WithFields(logrus.Fields{
			"prefix":      "proxy",
			"user_ip":     addrs,
			"server_name": outreq.Host,
			"user_id":     p.Gw.obfuscateKey(token),
			"user_name":   alias,
			"org_id":      p.TykAPISpec.OrgID,
			"api_id":      p.TykAPISpec.APIID,
		}).Error("http: proxy error: ", err)
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			p.ErrorHandler.HandleError(rw, logreq, "Upstream service reached hard timeout.", http.StatusGatewayTimeout, true)

			if p.TykAPISpec.Proxy.ServiceDiscovery.UseDiscoveryService {
				if ServiceCache != nil {
					p.logger.Debug("[PROXY] [SERVICE DISCOVERY] Upstream host failed, refreshing host list")
					ServiceCache.Delete(p.TykAPISpec.APIID)
				}
			}
			return ProxyResponse{UpstreamLatency: upstreamLatency}
		}

		if strings.Contains(err.Error(), "context canceled") {
			p.ErrorHandler.HandleError(rw, logreq, "Client closed request", 499, true)
			return ProxyResponse{UpstreamLatency: upstreamLatency}
		}

		if strings.Contains(err.Error(), "no such host") {
			p.ErrorHandler.HandleError(rw, logreq, "Upstream host lookup failed", http.StatusInternalServerError, true)
			return ProxyResponse{UpstreamLatency: upstreamLatency}
		}
		p.ErrorHandler.HandleError(rw, logreq, "There was a problem proxying the request", http.StatusInternalServerError, true)
		return ProxyResponse{UpstreamLatency: upstreamLatency}

	}

	if isHijacked {
		return ProxyResponse{UpstreamLatency: upstreamLatency}
	}

	upgrade, _ := p.IsUpgrade(req)
	// Deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	if upgrade {
		if err := p.handleUpgradeResponse(rw, outreq, res); err != nil {
			p.ErrorHandler.HandleError(rw, logreq, err.Error(), http.StatusInternalServerError, true)
			return ProxyResponse{UpstreamLatency: upstreamLatency}
		}
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
		return ProxyResponse{UpstreamLatency: upstreamLatency}
	}

	if err != nil {
		p.logger.Error("Response chain failed! ", err)
	}

	inres := new(http.Response)
	if withCache {
		*inres = *res // includes shallow copies of maps, but okay

		if !upgrade {
			defer res.Body.Close()

			// Buffer body data
			var bodyBuffer bytes.Buffer
			bodyBuffer2 := new(bytes.Buffer)

			p.CopyResponse(&bodyBuffer, res.Body, p.flushInterval(res))
			*bodyBuffer2 = bodyBuffer

			// Create new ReadClosers so we can split output
			res.Body = ioutil.NopCloser(&bodyBuffer)
			inres.Body = ioutil.NopCloser(bodyBuffer2)
		}
	}

	// We should at least copy the status code in
	inres.StatusCode = res.StatusCode
	inres.ContentLength = res.ContentLength
	p.HandleResponse(rw, res, ses)
	return ProxyResponse{UpstreamLatency: upstreamLatency, Response: inres}
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
	if p.Gw.GetConfig().CloseConnections {
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

	copyHeader(rw.Header(), res.Header, p.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)

	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	// do not write on a hijacked connection
	if res.StatusCode != http.StatusSwitchingProtocols {
		rw.WriteHeader(res.StatusCode)
	}

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	p.CopyResponse(rw, res.Body, p.flushInterval(res))

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer, p.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)
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

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (p *ReverseProxy) flushInterval(res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if resCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// We might have the case of streaming for which Content-Length might be unset.
	if res.ContentLength == -1 {
		return -1
	}

	return p.FlushInterval
}

func (p *ReverseProxy) CopyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) {

	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()

			// set up initial timer so headers get flushed even if body writes are delayed
			mlw.flushPending = true
			mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)

			dst = mlw
		}
	}

	p.copyBuffer(dst, src)
}

func (p *ReverseProxy) copyBuffer(dst io.Writer, src io.Reader) (int64, error) {

	buf := p.sp.Get().(*[]byte)
	defer p.sp.Put(buf)

	var written int64
	for {
		nr, rerr := src.Read(*buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			p.logger.WithFields(logrus.Fields{
				"prefix": "proxy",
				"org_id": p.TykAPISpec.OrgID,
				"api_id": p.TykAPISpec.APIID,
			}).Error("http: proxy error during body copy: ", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write((*buf)[:nr])
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

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return strings.ToLower(h.Get("Upgrade"))
}

func (p *ReverseProxy) handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response) error {
	copyHeader(res.Header, rw.Header(), p.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey)

	hj, ok := rw.(http.Hijacker)
	if !ok {
		return fmt.Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw)
	}
	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		return fmt.Errorf("internal error: 101 switching protocols response with non-writable body")
	}
	backConnCloseCh := make(chan bool)
	go func() {
		// Ensure that the cancelation of a request closes the backend.
		// See issue https://golang.org/issue/35559.
		select {
		case <-req.Context().Done():
		case <-backConnCloseCh:
		}
		backConn.Close()
	}()

	defer close(backConnCloseCh)
	conn, brw, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("Hijack failed on protocol switch: %v", err)
	}
	defer conn.Close()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}
	if err := brw.Flush(); err != nil {
		return fmt.Errorf("response flush: %v", err)
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc

	res.Body = ioutil.NopCloser(strings.NewReader(""))

	return nil
}

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	_, err := io.Copy(c.user, c.backend)
	errc <- err
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	_, err := io.Copy(c.backend, c.user)
	errc <- err
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err = m.dst.Write(p)
	if m.latency < 0 {
		m.dst.Flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.dst.Flush()
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

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
	_, err := io.Copy(&bodyRead, body)
	if err != nil {
		log.Error("copyBody failed", err)
	}

	// use seek-able reader for further body usage
	reusableBody := bytes.NewReader(bodyRead.Bytes())

	return nopCloser{reusableBody}
}

func copyRequest(r *http.Request) *http.Request {
	if r.ContentLength == -1 &&
		// for unknown length, if request is not gRPC we assume it's chunked transfer encoding
		IsGrpcStreaming(r) {
		return r
	}

	if r.Body != nil {
		r.Body = copyBody(r.Body)
	}
	return r
}

func copyResponse(r *http.Response) *http.Response {
	// for the case of streaming for which Content-Length might be unset = -1.

	if r.ContentLength == -1 {
		return r
	}

	// If the response is 101 Switching Protocols then the body will contain a
	// `*http.readWriteCloserBody` which cannot be copied (see stdlib documentation).
	// In this case we want to return immediately to avoid a silent crash.
	if r.StatusCode == http.StatusSwitchingProtocols {
		return r
	}

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

func (p *ReverseProxy) IsUpgrade(req *http.Request) (bool, string) {
	if !p.Gw.GetConfig().HttpServerOptions.EnableWebSockets {
		return false, ""
	}

	connection := strings.ToLower(strings.TrimSpace(req.Header.Get(headers.Connection)))
	if connection != "upgrade" {
		return false, ""
	}

	upgrade := strings.ToLower(strings.TrimSpace(req.Header.Get("Upgrade")))
	if upgrade != "" {
		return true, upgrade
	}

	return false, ""
}

// IsGrpcStreaming  determines wether a request represents a grpc streaming req
func IsGrpcStreaming(r *http.Request) bool {
	return r.ContentLength == -1 &&
		// gRPC over HTTP/2 requests content-type should begin with "application/grpc"
		strings.HasPrefix(r.Header.Get(headers.ContentType), "application/grpc")
}
