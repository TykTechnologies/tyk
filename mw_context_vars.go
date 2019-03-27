package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/request"
)

type MiddlewareContextVars struct {
	BaseMiddleware
}

func (m *MiddlewareContextVars) Name() string {
	return "MiddlewareContextVars"
}

func (m *MiddlewareContextVars) EnabledForSpec() bool {
	return m.Spec.EnableContextVars
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *MiddlewareContextVars) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	// https://golang.org/pkg/net/http/#Request.ParseForm
	// ParseForm drains the request body for a request with Content-Type of
	// application/x-www-form-urlencoded
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		var b bytes.Buffer
		r.Body = ioutil.NopCloser(io.TeeReader(r.Body, &b))

		r.ParseForm()

		r.Body = ioutil.NopCloser(&b)
	} else {
		r.ParseForm()
	}

	contextDataObject := map[string]interface{}{
		"request_data": r.Form, // Form params (map[string][]string)
		"headers":      map[string][]string(r.Header),
		"headers_Host": r.Host,
		"path_parts":   strings.Split(r.URL.Path, "/"), // Path parts
		"path":         r.URL.Path,                     // path data
		"remote_addr":  request.RealIP(r),              // IP
		"request_id":   uuid.NewV4().String(),          //Correlation ID
	}

	for hname, vals := range r.Header {
		n := "headers_" + strings.Replace(hname, "-", "_", -1)
		contextDataObject[n] = vals[0]
	}

	for _, c := range r.Cookies() {
		name := "cookies_" + strings.Replace(c.Name, "-", "_", -1)
		contextDataObject[name] = c.Value
	}

	ctxSetData(r, contextDataObject)

	return nil, http.StatusOK
}
