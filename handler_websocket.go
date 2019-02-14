package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/request"

	"github.com/TykTechnologies/tyk/config"
)

func canonicalAddr(url *url.URL) string {
	addr := url.Host
	// If the addr has a port number attached
	if !(strings.LastIndex(addr, ":") > strings.LastIndex(addr, "]")) {
		return addr + ":80"
	}
	return addr
}

type WSDialer struct {
	*http.Transport
	RW        http.ResponseWriter
	TLSConfig *tls.Config
}

func (ws *WSDialer) RoundTrip(req *http.Request) (*http.Response, error) {

	if !config.Global().HttpServerOptions.EnableWebSockets {
		return nil, errors.New("WebSockets has been disabled on this host")
	}

	target := canonicalAddr(req.URL)
	ip := request.RealIP(req)

	// TLS
	dial := ws.DialContext
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}

	// We do not get this WSS scheme, need another way to identify it
	switch req.URL.Scheme {
	case "wss", "https":
		var tlsConfig *tls.Config
		if ws.TLSClientConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = ws.TLSClientConfig
		}

		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := ws.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			//tlsConn.Handshake requires either ServerName or InsecureSkipVerify to be configured
			tlsConfig.ServerName, _, _ = net.SplitHostPort(address)

			tlsConn := tls.Client(conn, tlsConfig)
			err = tlsConn.Handshake()
			return tlsConn, err
		}
	}

	conn, err := dial(context.TODO(), "tcp", target)
	if err != nil {
		http.Error(ws.RW, "Error contacting backend server.", http.StatusInternalServerError)
		log.WithFields(logrus.Fields{
			"path":   target,
			"origin": ip,
		}).Error("Error dialing websocket backend", target, ": ", err)
		return nil, err
	}
	defer conn.Close()

	hj, ok := ws.RW.(http.Hijacker)
	if !ok {
		http.Error(ws.RW, "Not a hijacker?", http.StatusInternalServerError)
		return nil, errors.New("Not a hjijacker?")
	}

	nc, _, err := hj.Hijack()
	if err != nil {
		log.WithFields(logrus.Fields{
			"path":   req.URL.Path,
			"origin": ip,
		}).Errorf("Hijack error: %v", err)
		return nil, err
	}
	defer nc.Close()

	if err := req.Write(conn); err != nil {
		log.WithFields(logrus.Fields{
			"path":   req.URL.Path,
			"origin": ip,
		}).Errorf("Error copying request to target: %v", err)
		return nil, err
	}

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go cp(conn, nc)
	go cp(nc, conn)

	for i := 0; i < 2; i++ {
		cerr := <-errc
		if cerr == nil {
			continue
		}
		err = cerr
		log.WithFields(logrus.Fields{
			"path":   req.URL.Path,
			"origin": ip,
		}).Errorf("Error transmitting request: %v", err)
	}

	return nil, err
}

func IsWebsocket(req *http.Request) bool {
	if !config.Global().HttpServerOptions.EnableWebSockets {
		return false
	}

	connection := strings.ToLower(strings.TrimSpace(req.Header.Get("Connection")))
	if connection != "upgrade" {
		return false
	}

	upgrade := strings.ToLower(strings.TrimSpace(req.Header.Get("Upgrade")))
	return upgrade == "websocket"
}
