package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/TykTechnologies/again"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/tcp"
	"github.com/pires/go-proxyproto"

	"golang.org/x/net/http2"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
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
				DialTLS:         dialTLSPinnedCheck(spec, tlsConfig),
				TLSConfigTarget: tlsConfig,
			},
		}
		p.tcpProxy.AddDomainHandler(hostname, spec.Proxy.TargetURL, modifier)
		m.proxies = append(m.proxies, p)
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
			} else {
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

func (m *proxyMux) generateListener(listenPort int, protocol string) (l net.Listener, err error) {
	listenAddress := config.Global().ListenAddress
	disabled := config.Global().DisabledPorts
	for _, d := range disabled {
		if d.Protocol == protocol && d.Port == listenPort {
			return nil, fmt.Errorf("%s:%s trying to open disabled port", protocol, listenPort)
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
