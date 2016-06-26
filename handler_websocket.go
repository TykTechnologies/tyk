package main

import (
	"errors"
	"github.com/Sirupsen/logrus"
	"io"
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
	RW http.ResponseWriter
}

func (ws *WSDialer) RoundTrip(req *http.Request) (*http.Response, error) {
	target := canonicalAddr(req.URL)

	d, err := ws.Dial("tcp", target)
	defer d.Close()
	if err != nil {
		http.Error(ws.RW, "Error contacting backend server.", 500)
		log.WithFields(logrus.Fields{
			"path":   target,
			"origin": GetIPFromRequest(req),
		}).Error("Error dialing websocket backend %s: %v", target, err)
		return nil, err
	}

	hj, ok := ws.RW.(http.Hijacker)
	if !ok {
		http.Error(ws.RW, "Not a hijacker?", 500)
		return nil, errors.New("Not a hjijacker?")
	}

	nc, _, err := hj.Hijack()
	defer nc.Close()
	if err != nil {
		log.WithFields(logrus.Fields{
			"path":   req.URL.Path,
			"origin": GetIPFromRequest(req),
		}).Error("Hijack error: %v", err)
		return nil, err
	}

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
