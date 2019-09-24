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

	"github.com/TykTechnologies/again"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/tcp"
	proxyproto "github.com/pires/go-proxyproto"
	cache "github.com/pmylund/go-cache"

	"golang.org/x/net/http2"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// handleWrapper's only purpose is to allow router to be dynamically replaced
type handleWrapper struct {
	router *mux.Router
}

func (h *handleWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// make request body to be nopCloser and re-readable before serve it through chain of middlewares
	nopCloseRequestBody(r)
	if NewRelicApplication != nil {
		txn := NewRelicApplication.StartTransaction(r.URL.Path, w, r)
		defer txn.End()
		h.router.ServeHTTP(txn, r)
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
	proxies []*proxy
	again   again.Again
}

var defaultProxyMux = &proxyMux{
	again: again.New(),
}

func (m *proxyMux) getProxy(listenPort int) *proxy {
	if listenPort == 0 {
		listenPort = config.Global().ListenPort
	}

	for _, p := range m.proxies {
		if p.port == listenPort {
			return p
		}
	}

	return nil
}

func (m *proxyMux) router(port int, protocol string) *mux.Router {
	if protocol == "" {
		if config.Global().HttpServerOptions.UseSSL {
			protocol = "https"
		} else {
			protocol = "http"
		}
	}

	if proxy := m.getProxy(port); proxy != nil {
		if proxy.protocol != protocol {
			mainLog.WithField("port", port).Warningf("Can't get router for protocol %s, router for protocol %s found", protocol, proxy.protocol)
			return nil
		}

		return proxy.router
	}

	return nil
}

func (m *proxyMux) setRouter(port int, protocol string, router *mux.Router) {
	if port == 0 {
		port = config.Global().ListenPort
	}

	if protocol == "" {
		if config.Global().HttpServerOptions.UseSSL {
			protocol = "https"
		} else {
			protocol = "http"
		}
	}

	router.SkipClean(config.Global().HttpServerOptions.SkipURLCleaning)
	p := m.getProxy(port)
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

func (m *proxyMux) addTCPService(spec *APISpec, modifier *tcp.Modifier) {
	hostname := spec.GlobalConfig.HostName
	if spec.GlobalConfig.EnableCustomDomains {
		hostname = spec.Domain
	} else {
		hostname = ""
	}

	if p := m.getProxy(spec.ListenPort); p != nil {
		p.tcpProxy.AddDomainHandler(hostname, spec.Proxy.TargetURL, modifier)
	} else {
		tlsConfig := tlsClientConfig(spec)

		p = &proxy{
			port:             spec.ListenPort,
			protocol:         spec.Protocol,
			useProxyProtocol: spec.EnableProxyProtocol,
			tcpProxy: &tcp.Proxy{
				DialTLS:         dialWithServiceDiscovery(spec, dialTLSPinnedCheck(spec, tlsConfig)),
				Dial:            dialWithServiceDiscovery(spec, net.Dial),
				TLSConfigTarget: tlsConfig,
				SyncStats:       recordTCPHit(spec.APIID, spec.DoNotTrack),
			},
		}
		p.tcpProxy.AddDomainHandler(hostname, spec.Proxy.TargetURL, modifier)
		m.proxies = append(m.proxies, p)
	}
}

func flushNetworkAnalytics(ctx context.Context) {
	mainLog.Debug("Starting routine for flushing network analytics")
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-tick.C:

			apisMu.RLock()
			for _, spec := range apiSpecs {
				switch spec.Protocol {
				case "tcp", "tls":
					// we only flush network analytics for these services
				default:
					continue
				}
				if spec.DoNotTrack {
					continue
				}
				record := AnalyticsRecord{
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
				analytics.RecordHit(&record)
			}
			apisMu.RUnlock()
		}
	}
}

func recordTCPHit(specID string, doNotTrack bool) func(tcp.Stat) {
	if doNotTrack {
		return nil
	}
	return func(stat tcp.Stat) {
		// Between reloads, pointers to the actual spec might have changed. The spec
		// id stays the same so we need to pic the latest refence to the spec and
		// update network stats.
		apisMu.RLock()
		spec := apisByID[specID]
		apisMu.RUnlock()
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

func dialWithServiceDiscovery(spec *APISpec, dial dialFn) dialFn {
	if dial == nil {
		return nil
	}
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
	return func(network, address string) (net.Conn, error) {
		hostList := spec.Proxy.StructuredTargetList
		target := address
		switch {
		case spec.Proxy.ServiceDiscovery.UseDiscoveryService:
			var err error
			hostList, err = urlFromService(spec)
			if err != nil {
				log.Error("[PROXY] [SERVICE DISCOVERY] Failed target lookup: ", err)
				break
			}
			log.Debug("[PROXY] [SERVICE DISCOVERY] received host list ", hostList.All())
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

func (m *proxyMux) swap(new *proxyMux) {
	m.Lock()
	defer m.Unlock()
	listenAddress := config.Global().ListenAddress

	// Shutting down and removing unused listeners/proxies
	i := 0
	for _, curP := range m.proxies {
		match := new.getProxy(curP.port)
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
		match := m.getProxy(newP.port)
		if match == nil {
			m.proxies = append(m.proxies, newP)
		} else {
			if match.tcpProxy != nil {
				match.tcpProxy.Swap(newP.tcpProxy)
			}
			match.router = newP.router
			if match.httpServer != nil {
				match.httpServer.Handler.(*handleWrapper).router = newP.router
			}
		}
	}
	p := m.getProxy(config.Global().ListenPort)
	if p != nil && p.router != nil {
		// All APIs processed, now we can healthcheck
		// Add a root message to check all is OK
		p.router.HandleFunc("/"+config.Global().HealthCheckEndpointName, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "Hello Tiki")
		})
	}
	m.serve()
}

func (m *proxyMux) serve() {
	for _, p := range m.proxies {
		if p.listener == nil {
			listener, err := m.generateListener(p.port, p.protocol)
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
		case "http", "https":
			mainLog.Warning("Starting HTTP server on:", p.listener.Addr().String())
			readTimeout := 120 * time.Second
			writeTimeout := 120 * time.Second

			if config.Global().HttpServerOptions.ReadTimeout > 0 {
				readTimeout = time.Duration(config.Global().HttpServerOptions.ReadTimeout) * time.Second
			}

			if config.Global().HttpServerOptions.WriteTimeout > 0 {
				writeTimeout = time.Duration(config.Global().HttpServerOptions.WriteTimeout) * time.Second
			}

			addr := config.Global().ListenAddress + ":" + strconv.Itoa(p.port)
			p.httpServer = &http.Server{
				Addr:         addr,
				ReadTimeout:  readTimeout,
				WriteTimeout: writeTimeout,
				Handler:      &handleWrapper{p.router},
			}

			if config.Global().CloseConnections {
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

func (m *proxyMux) generateListener(listenPort int, protocol string) (l net.Listener, err error) {
	listenAddress := config.Global().ListenAddress
	if !config.Global().DisablePortWhiteList {
		if err := CheckPortWhiteList(config.Global().PortWhiteList, listenPort, protocol); err != nil {
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
		httpServerOptions := config.Global().HttpServerOptions

		tlsConfig := tls.Config{
			GetCertificate:     dummyGetCertificate,
			ServerName:         httpServerOptions.ServerName,
			MinVersion:         httpServerOptions.MinVersion,
			ClientAuth:         tls.NoClientCert,
			InsecureSkipVerify: httpServerOptions.SSLInsecureSkipVerify,
			CipherSuites:       getCipherAliases(httpServerOptions.Ciphers),
		}

		if httpServerOptions.EnableHttp2 {
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, http2.NextProtoTLS)
		}

		tlsConfig.GetConfigForClient = getTLSConfigForClient(&tlsConfig, listenPort)
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
