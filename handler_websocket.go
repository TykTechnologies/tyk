package main

import (
	"crypto/tls"
	"errors"
	"github.com/TykTechnologies/logrus"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	TykTransporter
	RW        http.ResponseWriter
	TLSConfig *tls.Config
}

func (ws *WSDialer) RoundTrip(req *http.Request) (*http.Response, error) {

	if !config.HttpServerOptions.EnableWebSockets {
		return nil, errors.New("WebSockets has been disabled on this host")
	}

	target := canonicalAddr(req.URL)

	// TLS
	dial := ws.Dial
	if dial == nil {
		dial = net.Dial
	}

	// We do not get this WSS scheme, need another way to identify it
	if req.URL.Scheme == "wss" || req.URL.Scheme == "https" {
		var tlsConfig *tls.Config
		if ws.TLSClientConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = ws.TLSClientConfig
		}
		dial = func(network, address string) (net.Conn, error) {
			return tls.Dial("tcp", target, tlsConfig)
		}
	}

	d, err := dial("tcp", target)
	if err != nil {
		http.Error(ws.RW, "Error contacting backend server.", 500)
		log.WithFields(logrus.Fields{
			"path":   target,
			"origin": GetIPFromRequest(req),
		}).Error("Error dialing websocket backend", target, ": ", err)
		return nil, err
	}
	defer d.Close()

	hj, ok := ws.RW.(http.Hijacker)
	if !ok {
		http.Error(ws.RW, "Not a hijacker?", 500)
		return nil, errors.New("Not a hjijacker?")
	}

	nc, _, err := hj.Hijack()
	if err != nil {
		log.WithFields(logrus.Fields{
			"path":   req.URL.Path,
			"origin": GetIPFromRequest(req),
		}).Error("Hijack error: %v", err)
		return nil, err
	}
	defer nc.Close()

	err = req.Write(d)
	if err != nil {
		log.WithFields(logrus.Fields{
			"path":   req.URL.Path,
			"origin": GetIPFromRequest(req),
		}).Error("Error copying request to target: %v", err)
		return nil, err
	}

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go cp(d, nc)
	go cp(nc, d)

	<-errc

	return nil, nil
}

func IsWebsocket(req *http.Request) bool {
	if !config.HttpServerOptions.EnableWebSockets {
		return false
	}

	connection := strings.ToLower(strings.TrimSpace(req.Header.Get("Connection")))
	if connection != "upgrade" {
		return false
	}

	upgrade := strings.ToLower(strings.TrimSpace(req.Header.Get("Upgrade")))
	if upgrade != "websocket" {
		return false
	}
	return true
}
