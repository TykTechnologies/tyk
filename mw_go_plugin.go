package main

import (
	"fmt"
	"net/http"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/goplugin"
)

// customResponseWriter is a wrapper around standard http.ResponseWriter
// plus it tracks if response was sent and what status code was sent
type customResponseWriter struct {
	http.ResponseWriter
	responseSent   bool
	statusCodeSent int
}

func (w *customResponseWriter) Write(b []byte) (int, error) {
	w.responseSent = true
	if w.statusCodeSent == 0 {
		w.statusCodeSent = http.StatusOK // no WriteHeader was called so it will be set to StatusOK in actual ResponseWriter
	}
	return w.ResponseWriter.Write(b)
}

func (w *customResponseWriter) WriteHeader(statusCode int) {
	w.responseSent = true
	w.statusCodeSent = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// GoPluginMiddleware is a generic middleware that will execute Go-plugin code before continuing
type GoPluginMiddleware struct {
	BaseMiddleware
	Path       string // path to .so file
	SymbolName string // function symbol to look up
	handler    http.HandlerFunc
	logger     *logrus.Entry
}

func (m *GoPluginMiddleware) Name() string {
	return "GoPluginMiddleware: " + m.Path + ":" + m.SymbolName
}

func (m *GoPluginMiddleware) EnabledForSpec() bool {
	m.logger = log.WithFields(logrus.Fields{
		"mwPath":       m.Path,
		"mwSymbolName": m.SymbolName,
	})

	if m.handler != nil {
		m.logger.Info("Go-plugin middleware is already initialized")
		return true
	}

	// try to load plugin
	var err error
	if m.handler, err = goplugin.GetHandler(m.Path, m.SymbolName); err != nil {
		m.logger.WithError(err).Error("Could not load Go-plugin")
		return false
	}

	return true
}

func (m *GoPluginMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (err error, respCode int) {
	// make sure tyk recover in case Go-plugin function panics
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
			respCode = http.StatusInternalServerError
			m.logger.WithError(err).Error("Recovered from panic while running Go-plugin middleware func")
		}
	}()

	// prepare data to call Go-plugin function

	// get session hash before Go-plugin function call
	var prevMD5Hash string
	if session := ctxGetSession(r); session != nil {
		prevMD5Hash = session.MD5Hash()
	}

	// make sure request's body can be re-read again
	nopCloseRequestBody(r)

	// wrap ResponseWriter to check if response was sent
	rw := &customResponseWriter{
		ResponseWriter: w,
	}

	// call Go-plugin function
	m.handler(rw, r)

	// check if we need to schedule session update in case session was updated by Go-plugin
	// but update wasn't scheduled
	if prevMD5Hash != "" {
		if session := ctxGetSession(r); session != nil && prevMD5Hash != session.MD5Hash() {
			ctxScheduleSessionUpdate(r)
		}
	}

	// check if response was sent
	if rw.responseSent {
		// check if response code was an error one
		if rw.statusCodeSent >= http.StatusBadRequest {
			respCode = rw.statusCodeSent
			err = fmt.Errorf("plugin function sent error response code: %d", rw.statusCodeSent)
			m.logger.WithError(err).Error("Failed to process request with Go-plugin middleware func")
		} else {
			respCode = mwStatusRespond // no need to continue passing this request down to reverse proxy
		}
	} else {
		respCode = http.StatusOK
	}

	return
}
