package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/context"
)

func GetIPFromRequest(r *http.Request) string {
	remoteIPString := r.RemoteAddr
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ", ")
		remoteIPString = ips[0]
		log.Debug("X-Forwarded-For set, remote IP: ", remoteIPString)
	}

	//Split off port
	ipPort := strings.Split(remoteIPString, ":")
	if len(ipPort) > 1 {
		remoteIPString = ipPort[0]
	}

	return remoteIPString
}

func CopyHttpRequest(r *http.Request) *http.Request {
	reqCopy := new(http.Request)

	if r == nil {
		return reqCopy
	}

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
	if r == nil {
		return resCopy
	}

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
	if !config.EnforceOrgDataDeailLogging {
		return config.AnalyticsConfig.EnableDetailedRecording
	}

	// We are, so get session data
	ses, found := context.GetOk(r, OrgSessionContext)
	if !found {
		// no session found, use global config
		return config.AnalyticsConfig.EnableDetailedRecording
	}

	// Session found
	return ses.(SessionState).EnableDetailedRecording
}
