package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TykTechnologies/tyk-pump/analytics"

	"golang.org/x/net/http2/h2c"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/TykTechnologies/again"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/httputil"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/tcp"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// handleWrapper's only purpose is to allow router to be dynamically replaced
type handleWrapper struct {
	router http.Handler // *mux.Router

	maxContentLength   int64
	maxRequestBodySize int64
}

// h2cWrapper tracks handleWrapper for swapping w.router on reloads.
type h2cWrapper struct {
	w *handleWrapper
	h http.Handler
}

func (h *h2cWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.h.ServeHTTP(w, r)
}

func (h *handleWrapper) handleRequestLimits(w http.ResponseWriter, r *http.Request) (ok bool) {
	// Limit request body size
	if h.maxRequestBodySize > 0 {
		// if Content-Length is larger than the configured limit return a status 413
		if r.ContentLength > 0 && r.ContentLength > h.maxRequestBodySize {
			httputil.EntityTooLarge(w, r)
			return false
		}

		// in case the content length is wrong or not set limit the reader itself
		r.Body = http.MaxBytesReader(w, r.Body, h.maxRequestBodySize)
	}

	return true
}

func (h *handleWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Store request start time for accurate latency measurement including all middlewares
	ctxSetRequestStartTime(r, time.Now())

	if r.Body != nil {
		if !h.handleRequestLimits(w, r) {
			return
		}
	}

	if h.maxRequestBodySize > 0 {
		// this greedily reads in the request body and
		// make request body to be nopCloser and re-readable
		// before serve it through chain of middlewares
		if err := nopCloseRequestBodyErr(r); err != nil {
			if err.Error() == "http: request body too large" {
				httputil.EntityTooLarge(w, r)
				return
			}

			httputil.InternalServerError(w, r)
			return
		}
	} else {
		// this leaves the body on lazy read as before
		if _, err := copyRequest(r); err != nil {
			log.WithError(err).Error("Error reading request body")
			httputil.InternalServerError(w, r)
		}
	}

	// Test don't provide a router
	if h.router == nil {
		return
	}

	h.router.ServeHTTP(w, r)
}

type proxy struct {
	listener         net.Listener
	port             int
	protocol         string
	useProxyProtocol bool
	router           *mux.Router
	httpServer       *http.Server
	tcpProxy         *tcp.Proxy
	started          bool
}

func (p proxy) String() string {
	ls := ""
	if p.listener != nil {
		ls = p.listener.Addr().String()
	}
	return fmt.Sprintf("[proxy] :%d %s", p.port, ls)
}

// getListener returns a net.Listener for this proxy. If useProxyProtocol is
// true it wraps the underlying listener to support proxyprotocol.
func (p proxy) getListener() net.Listener {
	if p.useProxyProtocol {
		return &proxyproto.Listener{Listener: p.listener}
	}
	return p.listener
}

type proxyMux struct {
	sync.RWMutex
	proxies      []*proxy
	again        again.Again
	track404Logs bool
	gw           *Gateway
}

func (m *proxyMux) getProxy(listenPort int, conf config.Config) *proxy {
	if listenPort == 0 {
		listenPort = conf.ListenPort
	}

	for _, p := range m.proxies {
		if p.port == listenPort {
			return p
		}
	}

	return nil
}

func (m *proxyMux) router(port int, protocol string, conf config.Config) *mux.Router {
	if protocol == "" {
		if conf.HttpServerOptions.UseSSL {
			protocol = "https"
		} else {
			protocol = "http"
		}
	}

	if proxy := m.getProxy(port, conf); proxy != nil {
		if proxy.protocol != protocol {
			mainLog.WithField("port", port).Warningf("Can't get router for protocol %s, router for protocol %s found", protocol, proxy.protocol)
			return nil
		}

		return proxy.router
	}

	return nil
}

func (m *proxyMux) setRouter(port int, protocol string, router *mux.Router, conf config.Config) {

	if port == 0 {
		port = conf.ListenPort
	}

	if protocol == "" {
		if conf.HttpServerOptions.UseSSL {
			protocol = "https"
		} else {
			protocol = "http"
		}
	}

	router.SkipClean(conf.HttpServerOptions.SkipURLCleaning)
	p := m.getProxy(port, conf)
	if p == nil {
		p = &proxy{
			port:     port,
			protocol: protocol,
			router:   router,
		}
		m.proxies = append(m.proxies, p)
	} else {
		if p.protocol != protocol {
			mainLog.WithFields(logrus.Fields{
				"port":     port,
				"protocol": protocol,
			}).Warningf("Can't update router. Already found service with another protocol %s", p.protocol)
			return
		}
		p.router = router
	}
}

func (m *proxyMux) handle404(w http.ResponseWriter, r *http.Request) {
	if m.track404Logs {
		// Existing logging functionality
		requestMeta := fmt.Sprintf("%s %s %s", r.Method, r.URL.Path, r.Proto)
		log.WithField("request", requestMeta).WithField("origin", r.RemoteAddr).
			Error(http.StatusText(http.StatusNotFound))

		// NEW: Also create analytics record if gateway and analytics are available
		if m.gw != nil && m.gw.Analytics.Store != nil {
			clientIP := request.RealIP(r)

			// Check if analytics should be recorded (respects enable_analytics and ignored_ips)
			gwConfig := m.gw.GetConfig()
			if gwConfig.StoreAnalytics(clientIP) {
				t := time.Now()

				host := r.URL.Host
				if host == "" {
					host = r.Host
				}

				record := analytics.AnalyticsRecord{
					Method:        r.Method,
					Host:          host,
					Path:          r.URL.Path,
					RawPath:       r.URL.Path,
					RawRequest:    r.URL.RawQuery,
					ContentLength: r.ContentLength,
					UserAgent:     r.Header.Get("User-Agent"),
					Day:           t.Day(),
					Month:         t.Month(),
					Year:          t.Year(),
					Hour:          t.Hour(),
					ResponseCode:  http.StatusNotFound,
					APIKey:        "",
					TimeStamp:     t,
					APIVersion:    "",
					APIName:       "",
					APIID:         "",
					OrgID:         "",
					OauthID:       "",
					RequestTime:   0,
					IPAddress:     clientIP,
					Geo:           analytics.GeoData{},
					Network:       analytics.NetworkStats{},
					Latency: analytics.Latency{
						Total:    0,
						Upstream: 0,
					},
					Tags:      []string{"404", "path-not-found"},
					Alias:     "",
					TrackPath: false,
					ExpireAt:  t.Add(time.Duration(gwConfig.AnalyticsConfig.StorageExpirationTime) * time.Second),
				}

				// Enable GeoIP if configured
				if gwConfig.AnalyticsConfig.EnableGeoIP && m.gw.Analytics.GeoIPDB != nil {
					record.GetGeo(clientIP, m.gw.Analytics.GeoIPDB)
				}

				// Record the hit
				err := m.gw.Analytics.RecordHit(&record)
				if err != nil {
					mainLog.Errorf("Failed to record 404 analytics for stream on path '%s %s', %v", r.Method, r.URL.Path, err)
				}
			}
		}
	}

	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, http.StatusText(http.StatusNotFound))
}

func (m *proxyMux) addTCPService(spec *APISpec, modifier *tcp.Modifier, gw *Gateway) {
	conf := gw.GetConfig()
	hostname := spec.GlobalConfig.HostName
	if spec.GlobalConfig.EnableCustomDomains {
		hostname = spec.GetAPIDomain()
	} else {
		hostname = ""
	}

	if spec.ListenPort == spec.GlobalConfig.ListenPort {
		mainLog.WithFields(logrus.Fields{
			"prefix":   "gateway",
			"org_id":   spec.OrgID,
			"api_id":   spec.APIID,
			"api_name": spec.Name,
		}).Error("TCP service can't have the same port as main gateway listen port")
		return
	}

	if p := m.getProxy(spec.ListenPort, conf); p != nil {
		p.tcpProxy.AddDomainHandler(hostname, spec.Proxy.TargetURL, modifier)
	} else {
		tlsConfig := tlsClientConfig(spec, gw)

		p = &proxy{
			port:             spec.ListenPort,
			protocol:         spec.Protocol,
			useProxyProtocol: spec.EnableProxyProtocol,
			tcpProxy: &tcp.Proxy{
				DialTLS:         gw.dialWithServiceDiscovery(spec, gw.customDialTLSCheck(spec, tlsConfig)),
				Dial:            gw.dialWithServiceDiscovery(spec, net.Dial),
				TLSConfigTarget: tlsConfig,
				// SyncStats:       recordTCPHit(spec.APIID, spec.DoNotTrack),
			},
		}
		p.tcpProxy.AddDomainHandler(hostname, spec.Proxy.TargetURL, modifier)
		m.proxies = append(m.proxies, p)
	}
}

func (gw *Gateway) flushNetworkAnalytics(ctx context.Context) {
	mainLog.Debug("Starting routine for flushing network analytics")
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-tick.C:

			gw.apisMu.RLock()
			for _, spec := range gw.apiSpecs {
				switch spec.Protocol {
				case "tcp", "tls":
					// we only flush network analytics for these services
				default:
					continue
				}
				if spec.DoNotTrack {
					continue
				}
				record := analytics.AnalyticsRecord{
					Network:      spec.network.Flush(),
					Day:          t.Day(),
					Month:        t.Month(),
					Year:         t.Year(),
					Hour:         t.Hour(),
					ResponseCode: -1,
					TimeStamp:    t,
					APIName:      spec.Name,
					APIID:        spec.APIID,
					OrgID:        spec.OrgID,
				}
				record.SetExpiry(spec.ExpireAnalyticsAfter)
				_ = gw.Analytics.RecordHit(&record)
			}
			gw.apisMu.RUnlock()
		}
	}
}

// nolint
func (gw *Gateway) recordTCPHit(specID string, doNotTrack bool) func(tcp.Stat) {
	if doNotTrack {
		return nil
	}
	return func(stat tcp.Stat) {
		// Between reloads, pointers to the actual spec might have changed. The spec
		// id stays the same so we need to pic the latest refence to the spec and
		// update network stats.
		gw.apisMu.RLock()
		spec := gw.apisByID[specID]
		gw.apisMu.RUnlock()
		switch stat.State {
		case tcp.Open:
			atomic.AddInt64(&spec.network.OpenConnections, 1)
		case tcp.Closed:
			atomic.AddInt64(&spec.network.ClosedConnection, 1)
		}
		atomic.AddInt64(&spec.network.BytesIn, stat.BytesIn)
		atomic.AddInt64(&spec.network.BytesOut, stat.BytesOut)
	}
}

type dialFn func(network string, address string) (net.Conn, error)

func (gw *Gateway) dialWithServiceDiscovery(spec *APISpec, dial dialFn) dialFn {
	if dial == nil {
		return nil
	}

	return func(network, address string) (net.Conn, error) {
		hostList := spec.Proxy.StructuredTargetList
		target := address
		switch {
		case spec.Proxy.ServiceDiscovery.UseDiscoveryService:
			var err error
			hostList, err = urlFromService(spec, gw)
			if err != nil {
				log.Error("[PROXY] [SERVICE DISCOVERY] Failed target lookup: ", err)
				break
			}
			log.Debug("[PROXY] [SERVICE DISCOVERY] received host list ", hostList.All())
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
				if lbRemote.Scheme == network {
					target = lbRemote.Host
				} else {
					log.Errorf("[PROXY] [LOAD BALANCING] mis match scheme want:%s got: %s", network, lbRemote.Scheme)
				}
			}
		}
		return dial(network, target)
	}
}

func (m *proxyMux) swap(new *proxyMux, gw *Gateway) {
	conf := gw.GetConfig()
	m.Lock()
	defer m.Unlock()
	listenAddress := conf.ListenAddress

	// Shutting down and removing unused listeners/proxies
	i := 0
	for _, curP := range m.proxies {
		match := new.getProxy(curP.port, conf)
		if match == nil || match.protocol != curP.protocol {
			mainLog.Infof("Found unused listener at port %d, shutting down", curP.port)

			if curP.httpServer != nil {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
				curP.httpServer.Shutdown(ctx)
				cancel()
			} else if curP.listener != nil {
				curP.listener.Close()
			}
			m.again.Delete(target(listenAddress, curP.port))
		} else {
			m.proxies[i] = curP
			i++
		}
	}
	m.proxies = m.proxies[:i]

	// Replacing existing routers or starting new listeners
	for _, newP := range new.proxies {
		match := m.getProxy(newP.port, conf)
		if match == nil {
			m.proxies = append(m.proxies, newP)
		} else {
			if match.tcpProxy != nil {
				match.tcpProxy.Swap(newP.tcpProxy)
			}
			match.router = newP.router
			if match.httpServer != nil {
				switch e := match.httpServer.Handler.(type) {
				case *handleWrapper:
					e.router = newP.router
				case *h2cWrapper:
					e.w.router = newP.router
				}
			}
		}
	}

	m.serve(gw)
}

func (m *proxyMux) serve(gw *Gateway) {
	conf := gw.GetConfig()
	for _, p := range m.proxies {
		if p.listener == nil {
			listener, err := m.generateListener(p.port, p.protocol, gw)
			if err != nil {
				mainLog.WithError(err).Error("Can't start listener")
				continue
			}

			_, portS, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portS)
			p.port = port
			p.listener = listener
		}
		if p.started {
			continue
		}
		switch p.protocol {
		case "tcp", "tls":
			mainLog.Warning("Starting TCP server on:", p.listener.Addr().String())
			go p.tcpProxy.Serve(p.getListener())
		case "http", "https", "h2c":
			mainLog.Warning("Starting HTTP server on:", p.listener.Addr().String())
			readTimeout := 120 * time.Second
			writeTimeout := 120 * time.Second

			if conf.HttpServerOptions.ReadTimeout > 0 {
				readTimeout = time.Duration(conf.HttpServerOptions.ReadTimeout) * time.Second
			}

			if conf.HttpServerOptions.WriteTimeout > 0 {
				writeTimeout = time.Duration(conf.HttpServerOptions.WriteTimeout) * time.Second
			}

			h := &handleWrapper{
				router:             p.router,
				maxRequestBodySize: conf.HttpServerOptions.MaxRequestBodySize,
			}

			// by default enabling h2c by wrapping handler in h2c. This ensures all features including tracing work
			// in h2c services.
			h2s := &http2.Server{}
			handler := &h2cWrapper{
				w: h,
				h: h2c.NewHandler(h, h2s),
			}

			addr := conf.ListenAddress + ":" + strconv.Itoa(p.port)
			p.httpServer = &http.Server{
				Addr:         addr,
				ReadTimeout:  readTimeout,
				WriteTimeout: writeTimeout,
				Handler:      handler,
			}
			if gw.ConnectionWatcher != nil {
				p.httpServer.ConnState = gw.ConnectionWatcher.OnStateChange
			}

			if conf.CloseConnections {
				p.httpServer.SetKeepAlivesEnabled(false)
			}
			go p.httpServer.Serve(p.listener)
		}
		p.started = true
	}
}

func target(listenAddress string, listenPort int) string {
	return fmt.Sprintf("%s:%d", listenAddress, listenPort)
}

func CheckPortWhiteList(w map[string]config.PortWhiteList, listenPort int, protocol string) error {

	if w != nil {
		if ls, ok := w[protocol]; ok {
			if ls.Match(listenPort) {
				return nil
			}
		}
	}

	return fmt.Errorf("%s:%d trying to open disabled port", protocol, listenPort)
}

func (m *proxyMux) generateListener(listenPort int, protocol string, gw *Gateway) (l net.Listener, err error) {
	conf := gw.GetConfig()
	listenAddress := conf.ListenAddress
	if !conf.DisablePortWhiteList {
		if err := CheckPortWhiteList(conf.PortWhiteList, listenPort, protocol); err != nil {
			return nil, err
		}
	}

	targetPort := listenAddress + ":" + strconv.Itoa(listenPort)
	if ls := m.again.GetListener(targetPort); ls != nil {
		return ls, nil
	}
	switch protocol {
	case "https", "tls":
		mainLog.Infof("--> Using TLS (%s)", protocol)
		httpServerOptions := conf.HttpServerOptions

		tlsConfig := tls.Config{
			GetCertificate:     dummyGetCertificate,
			ServerName:         httpServerOptions.ServerName,
			MinVersion:         httpServerOptions.MinVersion,
			MaxVersion:         httpServerOptions.MaxVersion,
			ClientAuth:         tls.NoClientCert,
			InsecureSkipVerify: httpServerOptions.SSLInsecureSkipVerify,
			CipherSuites:       getCipherAliases(httpServerOptions.Ciphers),
		}

		if httpServerOptions.EnableHttp2 {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, http2.NextProtoTLS)
		}

		tlsConfig.GetConfigForClient = gw.getTLSConfigForClient(&tlsConfig, listenPort)
		l, err = tls.Listen("tcp", targetPort, &tlsConfig)

	default:
		mainLog.WithField("port", targetPort).Infof("--> Standard listener (%s)", protocol)
		l, err = net.Listen("tcp", targetPort)
	}
	if err != nil {
		return nil, err
	}
	if err := (&m.again).Listen(targetPort, l); err != nil {
		return nil, err
	}
	return l, nil
}
