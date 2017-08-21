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

func CopyHttpRequest(r *http.Request) *http.Request {
	reqCopy := new(http.Request)
	*reqCopy = *r

	if r.Body != nil {
		defer r.Body.Close()

		// Buffer body data
		var bodyBuffer bytes.Buffer
		bodyBuffer2 := new(bytes.Buffer)

		io.Copy(&bodyBuffer, r.Body)
		*bodyBuffer2 = bodyBuffer

		// Create new ReadClosers so we can split output
		r.Body = ioutil.NopCloser(&bodyBuffer)
		reqCopy.Body = ioutil.NopCloser(bodyBuffer2)
	}

	return reqCopy
}

func CopyHttpResponse(r *http.Response) *http.Response {
	resCopy := new(http.Response)
	*resCopy = *r

	if r.Body != nil {
		defer r.Body.Close()

		// Buffer body data
		var bodyBuffer bytes.Buffer
		bodyBuffer2 := new(bytes.Buffer)

		io.Copy(&bodyBuffer, r.Body)
		*bodyBuffer2 = bodyBuffer

		// Create new ReadClosers so we can split output
		r.Body = ioutil.NopCloser(&bodyBuffer)
		resCopy.Body = ioutil.NopCloser(bodyBuffer2)
	}

	return resCopy
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
