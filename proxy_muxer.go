package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/config"

	"golang.org/x/net/http2"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
)

// handleWrapper's only purpose is to allow router to be dynamically replaced
type handleWrapper struct {
	router *mux.Router
}

func (h *handleWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	AddNewRelicInstrumentation(NewRelicApplication, h.router)

	// make request body to be nopCloser and re-readable before serve it through chain of middlewares
	nopCloseRequestBody(r)

	h.router.ServeHTTP(w, r)
}

type proxy struct {
	listener   net.Listener
	port       int
	protocol   string
	router     *mux.Router
	httpServer *http.Server
}

type proxyMux struct {
	sync.RWMutex
	proxies []*proxy
}

var defaultProxyMux = &proxyMux{}

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

func (m *proxyMux) swap(new *proxyMux) {
	m.Lock()
	defer m.Unlock()

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
			match.router = newP.router
		}
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

		if p.protocol != "http" && p.protocol != "https" {
			continue
		}

		// Swap the router without re-creating server
		if p.httpServer != nil {
			p.httpServer.Handler.(*handleWrapper).router = p.router
			continue
		}

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
}

func (m *proxyMux) generateListener(listenPort int, protocol string) (l net.Listener, err error) {
	listenAddress := config.Global().ListenAddress

	targetPort := listenAddress + ":" + strconv.Itoa(listenPort)

	if protocol == "https" || protocol == "tcps" {
		mainLog.Infof("--> Using SSL (%s)", protocol)
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
	} else {
		mainLog.WithField("port", targetPort).Infof("--> Standard listener (%s)", protocol)
		l, err = net.Listen("tcp", targetPort)
	}

	return l, err
}
