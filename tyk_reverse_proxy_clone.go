// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP reverse proxy handler

package main

import (
	"bytes"
	"crypto/tls"
	"github.com/TykTechnologies/logrus"
	"github.com/gorilla/context"
	"github.com/pmylund/go-cache"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/TykTechnologies/tykcommon"

)

var ServiceCache *cache.Cache

func GetURLFromService(spec *APISpec) (*tykcommon.HostList, error) {

	doCacheRefresh := func () (*tykcommon.HostList, error) {
		log.Debug("--> Refreshing")
		spec.ServiceRefreshInProgress = true
		sd := ServiceDiscovery{}
		sd.New(&spec.Proxy.ServiceDiscovery)
		data, err := sd.GetTarget(spec.Proxy.ServiceDiscovery.QueryEndpoint)	
		if err == nil {
			// Set the cached value
			if data.Len() == 0 {
				spec.HasRun = true
				spec.ServiceRefreshInProgress = false
				log.Warning("[PROXY][SD] Service Discovery returned empty host list! Returning last good set.")
				return spec.LastGoodHostList, nil
			}

			ServiceCache.Set(spec.APIID, data, cache.DefaultExpiration)
			// Stash it too
			spec.LastGoodHostList = data
			spec.HasRun = true
			spec.ServiceRefreshInProgress = false
			return data, err
		}
		spec.ServiceRefreshInProgress = false
		return nil, err
	}

	// First time? Refresh the cache and return that
	if !spec.HasRun {
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
		} else {
			// Refresh the spec
			log.Debug("Cache expired! Refreshing...")
			return doCacheRefresh()
		}
		
	}

	log.Debug("Returning from cache.")
	return cachedServiceData.(*tykcommon.HostList), nil
}

func EnsureTransport(host string) string {
	if strings.HasPrefix(host, "https://") {
		return host
	}

	if strings.HasPrefix(host, "http://") {
		return host
	}

	// no prototcol, assum ehttp
	host = "http://" + host
	return host
}

func GetNextTarget(targetData *tykcommon.HostList, spec *APISpec, tryCount int) string {
	if spec.Proxy.EnableLoadBalancing {
		log.Debug("[PROXY] [LOAD BALANCING] Load balancer enabled, getting upstream target")
		// Use a HostList
		spec.RoundRobin.SetMax(targetData)

		pos := spec.RoundRobin.GetPos()
		if pos > (targetData.Len() - 1) {
			// problem
			spec.RoundRobin.SetMax(targetData)
			pos = 0
		}

		gotHost, err := targetData.GetIndex(pos)
		if err != nil {
			log.Error("[PROXY] [LOAD BALANCING] ", err)
			return gotHost
		}

		thisHost := EnsureTransport(gotHost)

		// Check hosts against uptime tests
		if spec.Proxy.CheckHostAgainstUptimeTests {
			if !GlobalHostChecker.IsHostDown(thisHost) {
				// Don't overdo it
				if tryCount < targetData.Len() {
					// Host is down, skip
					return GetNextTarget(targetData, spec, tryCount+1)
				}
				log.Error("[PROXY] [LOAD BALANCING] All hosts seem to be down, all uptime tests are failing!")
			}
		}

		return thisHost
	}
	// Use standard target - might still be service data
	log.Debug("TARGET DATA:", targetData)

	gotHost, err := targetData.GetIndex(0)
	if err != nil {
		log.Error("[PROXY] ", err)
		return gotHost
	}
	return EnsureTransport(gotHost)
}

// TykNewSingleHostReverseProxy returns a new ReverseProxy that rewrites
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir. This version modifies the
// stdlib version by also setting the host to the target, this allows
// us to work with heroku and other such providers
func TykNewSingleHostReverseProxy(target *url.URL, spec *APISpec) *ReverseProxy {
	// initalise round robin
	spec.RoundRobin = &RoundRobin{}
	spec.RoundRobin.SetMax(tykcommon.NewHostList())

	if spec.Proxy.ServiceDiscovery.UseDiscoveryService {
		log.Debug("[PROXY] Service discovery enabled")
		if ServiceCache == nil {
			log.Debug("[PROXY] Service cache initialising")
			expiry := 120
			if config.ServiceDiscovery.DefaultCacheTimeout > 0 {
				expiry = config.ServiceDiscovery.DefaultCacheTimeout
			}
			ServiceCache = cache.New(time.Duration(expiry)*time.Second, 15*time.Second)
		}
	}

	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		var targetSet bool
		if spec.Proxy.ServiceDiscovery.UseDiscoveryService {
			tempTargetURL, tErr := GetURLFromService(spec)
			if tErr != nil {
				log.Error("[PROXY] [SERVICE DISCOVERY] Failed target lookup: ", tErr)
			} else {
				// No error, replace the target
				if spec.Proxy.EnableLoadBalancing {
					remote, err := url.Parse(GetNextTarget(tempTargetURL, spec, 0))
					if err != nil {
						log.Error("[PROXY] [SERVICE DISCOVERY] Couldn't parse target URL:", err)
					} else {
						// Only replace target if everything is OK
						target = remote
						targetQuery = target.RawQuery
					}
				} else {
					remote, err := url.Parse(GetNextTarget(tempTargetURL, spec, 0))
					if err != nil {
						log.Error("[PROXY] [SERVICE DISCOVERY] Couldn't parse target URL:", err)
					} else {
						// Only replace target if everything is OK
						target = remote
						targetQuery = target.RawQuery
					}
				}
			}
			// We've overriden remote now, don;t need to do it again
			targetSet = true
		}

		if !targetSet {
			// no override, better check if LB is enabled
			if spec.Proxy.EnableLoadBalancing {
				// it is, lets get that target data
				lbRemote, lbErr := url.Parse(GetNextTarget(&spec.Proxy.StructuredTargetList, spec, 0))
				if lbErr != nil {
					log.Error("[PROXY] [LOAD BALANCING] Couldn't parse target URL:", lbErr)
				} else {
					// Only replace target if everything is OK
					target = lbRemote
					targetQuery = target.RawQuery
				}
			}
		}

		// Specifically override with a URL rewrite
		var newTarget *url.URL
		switchTargets := false

		if spec.URLRewriteEnabled {
			URLRewriteContainsTarget, found := context.GetOk(req, RetainHost)
			if found {
				if URLRewriteContainsTarget.(bool) {
					log.Debug("Detected host rewrite, overriding target")
					tmpTarget, pErr := url.Parse(req.URL.String())
					if pErr != nil {
						log.Error("Failed to parse URL! Err: ", pErr)
					} else {
						newTarget = tmpTarget
						switchTargets = true
					}
					context.Clear(req)
				}
			}
		}

		// No override, and no load balancing? Use the existing target
		var targetToUse *url.URL = target
		if switchTargets {
			targetToUse = newTarget
		}
		req.URL.Scheme = targetToUse.Scheme
		req.URL.Host = targetToUse.Host
		req.URL.Path = singleJoiningSlash(targetToUse.Path, req.URL.Path)
		if !spec.Proxy.PreserveHostHeader {
			req.Host = targetToUse.Host
		}
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}

	return &ReverseProxy{Director: director, TykAPISpec: spec, FlushInterval: time.Duration(config.HttpServerOptions.FlushInterval) * time.Millisecond}
}

// onExitFlushLoop is a callback set by tests to detect the state of the
// flushLoop() goroutine.
var onExitFlushLoop func()

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

	TykAPISpec      *APISpec
	ErrorHandler    ErrorHandler
	ResponseHandler ResponseChain
}

type TykTransporter struct {
	http.Transport
}

func (t *TykTransporter) SetDialFunc(Dial func(string, string) (net.Conn, error)) {
	t.Dial = Dial
}

func (t *TykTransporter) SetTimeout(timeOut int) {
	//t.Dial.Timeout = time.Duration(timeOut) * time.Second
	t.ResponseHeaderTimeout = time.Duration(timeOut) * time.Second
}

func getMaxIdleConns() int {
	return config.MaxIdleConnsPerHost
}

var TykDefaultTransport *TykTransporter = &TykTransporter{http.Transport{
	Proxy: http.ProxyFromEnvironment,
	MaxIdleConnsPerHost: getMaxIdleConns(),
	Dial: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial,
	TLSHandshakeTimeout: 10 * time.Second,
}}

func cleanSlashes(a string) string {
	endSlash := strings.HasSuffix(a, "//")
	startSlash := strings.HasPrefix(a, "//")

	if startSlash {
		a = "/" + strings.TrimPrefix(a, "//")
	}

	if endSlash {
		a = strings.TrimSuffix(a, "//") + "/"
	}

	return a
}

func singleJoiningSlash(a, b string) string {
	a = cleanSlashes(a)
	b = cleanSlashes(b)

	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")

	switch {
	case aslash && bslash:
		log.Debug(a + b)
		return a + b[1:]
	case !aslash && !bslash:
		if len(b) > 0 {
			log.Debug(a + b)
			return a + "/" + b
		} else {
			log.Debug(a + b)
			return a
		}

	}
	log.Debug(a + b)
	return a + b
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func (p *ReverseProxy) ReturnRequestServeHttp(rw http.ResponseWriter, req *http.Request) *http.Request {
	outreq := new(http.Request)

	p.ServeHTTP(rw, req)

	return outreq
}

func (p *ReverseProxy) New(c interface{}, spec *APISpec) (TykResponseHandler, error) {
	p.ErrorHandler = ErrorHandler{TykMiddleware: &TykMiddleware{spec, p}}
	return nil, nil
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) *http.Response {
	return p.WrappedServeHTTP(rw, req, RecordDetail(req))
	// return nil
}

func (p *ReverseProxy) ServeHTTPForCache(rw http.ResponseWriter, req *http.Request) *http.Response {
	return p.WrappedServeHTTP(rw, req, true)
}

func (p *ReverseProxy) CheckHardTimeoutEnforced(spec *APISpec, req *http.Request) (bool, int) {
	if !spec.EnforcedTimeoutEnabled {
		return false, 0
	}

	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := spec.GetVersionData(req)
	found, meta = spec.CheckSpecMatchesStatus(req.URL.Path, req.Method, versionPaths, HardTimeout)
	if found {
		stat = StatusHardTimeout
	}

	if stat == StatusHardTimeout {
		thisMeta := meta.(*int)
		log.Debug("HARD TIMEOUT ENFORCED: ", *thisMeta)
		return true, *thisMeta
	}

	return false, 0
}

func (p *ReverseProxy) CheckCircuitBreakerEnforced(spec *APISpec, req *http.Request) (bool, *ExtendedCircuitBreakerMeta) {
	if !spec.CircuitBreakerEnabled {
		return false, nil
	}

	var stat RequestStatus
	var meta interface{}
	var found bool

	_, versionPaths, _, _ := spec.GetVersionData(req)
	found, meta = spec.CheckSpecMatchesStatus(req.URL.Path, req.Method, versionPaths, CircuitBreaker)
	if found {
		stat = StatusCircuitBreaker
	}

	if stat == StatusCircuitBreaker {
		thisMeta := meta.(*ExtendedCircuitBreakerMeta)
		log.Debug("CB Enforced for path: ", *thisMeta)
		return true, thisMeta
	}

	return false, nil
}

func GetTransport(timeOut int, rw http.ResponseWriter, req *http.Request, p *ReverseProxy) http.RoundTripper {
	var thisTransport *TykTransporter = TykDefaultTransport

	// Use the default unless we've modified the timout
	if timeOut > 0 {
		log.Debug("Setting timeout for outbound request to: ", timeOut)
		thisTransport.SetDialFunc((&net.Dialer{
			Timeout:   time.Duration(timeOut) * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial)
		thisTransport.SetTimeout(timeOut)

	}

	if IsWebsocket(req) {
		wsTransport := &WSDialer{*thisTransport, rw, p.TLSClientConfig}
		return wsTransport
	}

	return thisTransport
}

func (p *ReverseProxy) WrappedServeHTTP(rw http.ResponseWriter, req *http.Request, withCache bool) *http.Response {
	transport := p.Transport
	// 1. Check if timeouts are set for this endpoint
	_, timeout := p.CheckHardTimeoutEnforced(p.TykAPISpec, req)
	transport = GetTransport(timeout, rw, req, p)

	// Do this before we make a shallow copy
	sessVal := context.Get(req, SessionData)

	outreq := new(http.Request)
	logreq := new(http.Request)
	log.Debug("UPSTREAM REQUEST URL: ", req.URL)

	// We need to double set the context for the outbound request to reprocess the target
	if p.TykAPISpec.URLRewriteEnabled {
		URLRewriteContainsTarget, found := context.GetOk(req, RetainHost)
		if found {
			if URLRewriteContainsTarget.(bool) {
				log.Debug("Detected host rewrite, notifying director")
				context.Set(outreq, RetainHost, true)
			}
		}
	}

	*outreq = *req // includes shallow copies of maps, but okay
	*logreq = *req

	p.Director(outreq)

	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false

	log.Debug("Outbound Request: ", outreq.URL.String())

	// Do not modify outbound request headers if they are WS
	if !IsWebsocket(outreq) {

		// Remove hop-by-hop headers to the backend.  Especially
		// important is "Connection" because we want a persistent
		// connection, regardless of what the client sent to us.  This
		// is modifying the same underlying map from req (shallow
		// copied above) so we only copy it if necessary.
		copiedHeaders := false
		for _, h := range hopHeaders {
			if outreq.Header.Get(h) != "" {
				if !copiedHeaders {
					outreq.Header = make(http.Header)
					logreq.Header = make(http.Header)
					copyHeader(outreq.Header, req.Header)
					copyHeader(logreq.Header, req.Header)
					copiedHeaders = true
				}
				outreq.Header.Del(h)
				logreq.Header.Del(h)
			}
		}
	}

	var thisIP string
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
		thisIP = clientIP
	}

	// Circuit breaker
	breakerEnforced, breakerConf := p.CheckCircuitBreakerEnforced(p.TykAPISpec, req)

	var res *http.Response
	var err error
	if breakerEnforced {
		log.Debug("ON REQUEST: Breaker status: ", breakerConf.CB.Ready())
		if breakerConf.CB.Ready() {
			res, err = transport.RoundTrip(outreq)
			if err != nil {
				breakerConf.CB.Fail()
			} else if res.StatusCode == 500 {
				breakerConf.CB.Fail()
			} else {
				breakerConf.CB.Success()
			}
		} else {
			p.ErrorHandler.HandleError(rw, logreq, "Service temporarily unnavailable.", 503)
			return nil
		}
	} else {
		res, err = transport.RoundTrip(outreq)
	}

	if err != nil {

		var authHeaderValue string
		contextAuthVal, authOk := context.GetOk(req, AuthHeaderValue)
		if authOk {
			authHeaderValue = contextAuthVal.(string)
		}

		var obfuscated string
		if len(authHeaderValue) > 4 {
			obfuscated = "****" + authHeaderValue[len(authHeaderValue)-4:]
		}

		var alias string
		if sessVal != nil {
			alias = sessVal.(SessionState).Alias
		}

		log.WithFields(logrus.Fields{
			"prefix":      "proxy",
			"user_ip":     thisIP,
			"server_name": outreq.Host,
			"user_id":     obfuscated,
			"user_name":   alias,
			"org_id":      p.TykAPISpec.APIDefinition.OrgID,
			"api_id":      p.TykAPISpec.APIDefinition.APIID,
		}).Error("http: proxy error: ", err)

		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			p.ErrorHandler.HandleError(rw, logreq, "Upstream service reached hard timeout.", 408)

			if p.TykAPISpec.Proxy.ServiceDiscovery.UseDiscoveryService {
				if ServiceCache != nil {
					log.Debug("[PROXY] [SERVICE DISCOVERY] Upstream host failed, refreshing host list")
					ServiceCache.Delete(p.TykAPISpec.APIID)
				}
			}
			return nil
		}
		if strings.Contains(err.Error(), "no such host") {
			p.ErrorHandler.HandleError(rw, logreq, "Upstream host lookup failed", 500)
			return nil
		}

		p.ErrorHandler.HandleError(rw, logreq, "There was a problem proxying the request", 500)
		return nil

	}

	if IsWebsocket(req) {
		return nil
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

	ses := SessionState{}
	if sessVal != nil {
		ses = sessVal.(SessionState)
	}

	if p.TykAPISpec.ResponseHandlersActive {
		// Middleware chain handling here - very simple, but should do the trick
		chainErr := p.ResponseHandler.Go(p.TykAPISpec.ResponseChain, rw, res, req, &ses)
		if chainErr != nil {
			log.Error("Response chain failed! ", chainErr)
		}
	}

	// We should at least copy the status code in
	inres.StatusCode = res.StatusCode
	inres.ContentLength = res.ContentLength
	p.HandleResponse(rw, res, req, &ses)
	return inres
}

func (p *ReverseProxy) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *SessionState) error {

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}
	defer res.Body.Close()

	// Close connections
	if config.CloseConnections {
		res.Header.Set("Connection", "close")
	}

	// Add resource headers
	if ses != nil {
		// We have found a session, lets report back
		res.Header.Add("X-RateLimit-Limit", strconv.Itoa(int(ses.QuotaMax)))
		res.Header.Add("X-RateLimit-Remaining", strconv.Itoa(int(ses.QuotaRemaining)))
		res.Header.Add("X-RateLimit-Reset", strconv.Itoa(int(ses.QuotaRenews)))
	}

	copyHeader(rw.Header(), res.Header)

	rw.WriteHeader(res.StatusCode)
	p.CopyResponse(rw, res.Body)
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

	io.Copy(dst, src)
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration

	lk   sync.Mutex // protects Write + Flush
	done chan bool
}

func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.lk.Lock()
	defer m.lk.Unlock()
	return m.dst.Write(p)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			if onExitFlushLoop != nil {
				onExitFlushLoop()
			}
			return
		case <-t.C:
			m.lk.Lock()
			m.dst.Flush()
			m.lk.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() { m.done <- true }
