package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

func requestIP(r *http.Request) string {
	if fw := r.Header.Get("X-Forwarded-For"); fw != "" {
		// X-Forwarded-For has no port
		if i := strings.IndexByte(fw, ','); i >= 0 {
			return fw[:i]
		}
		return fw
	}

	// From net/http.Request.RemoteAddr:
	//   The HTTP server in this package sets RemoteAddr to an
	//   "IP:port" address before invoking a handler.
	// So we can ignore the case of the port missing.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
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

func copyRequest(r *http.Request) *http.Request {
	r2 := *r
	if r.Body != nil {
		defer r.Body.Close()

		var buf1, buf2 bytes.Buffer
		io.Copy(&buf1, r.Body)
		buf2 = buf1

		r.Body = ioutil.NopCloser(&buf1)
		r2.Body = ioutil.NopCloser(&buf2)
	}
	return &r2
}

func copyResponse(r *http.Response) *http.Response {
	r2 := *r
	if r.Body != nil {
		defer r.Body.Close()

		var buf1, buf2 bytes.Buffer
		io.Copy(&buf1, r.Body)
		buf2 = buf1

		r.Body = ioutil.NopCloser(&buf1)
		r2.Body = ioutil.NopCloser(&buf2)
	}
	return &r2
}

func RecordDetail(r *http.Request) bool {
	// Are we even checking?
	if !globalConf.EnforceOrgDataDeailLogging {
		return globalConf.AnalyticsConfig.EnableDetailedRecording
	}

	// We are, so get session data
	ses := r.Context().Value(OrgSessionContext)
	if ses == nil {
		// no session found, use global config
		return globalConf.AnalyticsConfig.EnableDetailedRecording
	}

	// Session found
	return ses.(SessionState).EnableDetailedRecording
}
