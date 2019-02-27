package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "net"
    "net/http"
    "strconv"
    "sync"
    "time"

    "github.com/TykTechnologies/tyk/config"

    "golang.org/x/net/http2"

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

func (m *proxyMux) router(listenPort int) *mux.Router {
    if proxy := m.getProxy(listenPort); proxy != nil {
        return proxy.httpServer.Handler.(*handleWrapper).router
    }

    return nil
}

func (m *proxyMux) updateRouter(listenPort int, router *mux.Router) {
    if proxy := m.getProxy(listenPort); proxy != nil {
        router.SkipClean(config.Global().HttpServerOptions.SkipURLCleaning)
        proxy.httpServer.Handler.(*handleWrapper).router = router
    } else {
        if err := m.serve(listenPort, ""); err != nil {
            return
        }

        m.updateRouter(listenPort, router)
    }
}

func (m *proxyMux) serve(listenPort int, protocol string) error {
    listener, err := m.generateListener(listenPort, protocol)
    if err != nil {
        mainLog.WithError(err).Error("Can't start server")
        return err
    }

    readTimeout := 120 * time.Second
    writeTimeout := 120 * time.Second

    if config.Global().HttpServerOptions.ReadTimeout > 0 {
        readTimeout = time.Duration(config.Global().HttpServerOptions.ReadTimeout) * time.Second
    }

    if config.Global().HttpServerOptions.WriteTimeout > 0 {
        writeTimeout = time.Duration(config.Global().HttpServerOptions.WriteTimeout) * time.Second
    }

    proxy := m.getProxy(listenPort)
    if proxy.httpServer != nil {
        return nil
    }

    router := mux.NewRouter()
    router.SkipClean(config.Global().HttpServerOptions.SkipURLCleaning)

    addr := config.Global().ListenAddress + ":" + strconv.Itoa(listenPort)
    proxy.httpServer = &http.Server{
        Addr:         addr,
        ReadTimeout:  readTimeout,
        WriteTimeout: writeTimeout,
        Handler:      &handleWrapper{router},
    }

    if config.Global().CloseConnections {
        proxy.httpServer.SetKeepAlivesEnabled(false)
    }

    go proxy.httpServer.Serve(listener)

    mainLog.Warning("Started a new server on ", addr)

    return nil
}

func (m *proxyMux) generateListener(listenPort int, protocol string) (l net.Listener, err error) {
    m.Lock()
    defer m.Unlock()

    // Default protocol
    if protocol == "" {
        if config.Global().HttpServerOptions.UseSSL {
            protocol = "https"
        } else {
            protocol = "http"
        }
    }

    if listenPort == 0 {
        listenPort = config.Global().ListenPort
    }

    // Special case for tests
    if listenPort == -1 {
        listenPort = 0
    }

    for _, p := range m.proxies {
        if p.port == listenPort {
            if p.protocol != protocol {
                return nil, fmt.Errorf("Can't use port `%d` for protocol `%s`. Listener with `%s` protocol already exist", p.port, protocol, p.protocol)
            }

            return p.listener, nil
        }
    }

    listenAddress := config.Global().ListenAddress

    targetPort := listenAddress + ":" + strconv.Itoa(listenPort)

    if httpServerOptions := config.Global().HttpServerOptions; httpServerOptions.UseSSL {
        mainLog.Info("--> Using SSL (https)")

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
    } else if config.Global().HttpServerOptions.UseLE_SSL {

        mainLog.Info("--> Using SSL LE (https)")

        GetLEState(&LE_MANAGER)

        conf := tls.Config{
            GetCertificate: LE_MANAGER.GetCertificate,
        }
        conf.GetConfigForClient = getTLSConfigForClient(&conf, listenPort)

        l, err = tls.Listen("tcp", targetPort, &conf)
    } else {
        mainLog.WithField("port", targetPort).Info("--> Standard listener (http)")
        l, err = net.Listen("tcp", targetPort)
    }

    if err == nil {
        // Handle 0 port, when it assigned after listener created
        _, portS, _ := net.SplitHostPort(l.Addr().String())
        port, _ := strconv.Atoi(portS)
        m.proxies = append(m.proxies, &proxy{
            listener: l,
            port:     port,
            protocol: protocol,
        })
    } else {
        panic(err.Error())
    }

    return l, err
}

func (m *proxyMux) cleanup(usedPorts []int) {
    m.Lock()
    defer m.Unlock()

    activeProxies := []*proxy{}
    for _, p := range m.proxies {
        found := false
        for _, port := range usedPorts {
            if port == p.port {
                found = true
                break
            }
        }

        if found {
            activeProxies = append(activeProxies, p)
            continue
        }

        mainLog.Infof("Found unused listener at port %d, shutting down", p.port)
        if p.httpServer != nil {
            ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
            p.httpServer.Shutdown(ctx)
            cancel()
        } else {
            p.listener.Close()
        }
    }

    m.proxies = activeProxies
}
