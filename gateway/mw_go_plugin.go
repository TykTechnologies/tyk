package gateway

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/v3/ctx"
	"github.com/TykTechnologies/tyk/v3/goplugin"
	"github.com/TykTechnologies/tyk/v3/request"
)

// customResponseWriter is a wrapper around standard http.ResponseWriter
// plus it tracks if response was sent and what status code was sent
type customResponseWriter struct {
	http.ResponseWriter
	responseSent   bool
	statusCodeSent int
	copyData       bool
	data           []byte
	dataLength     int64
}

func (w *customResponseWriter) Write(b []byte) (int, error) {
	w.responseSent = true
	if w.statusCodeSent == 0 {
		w.statusCodeSent = http.StatusOK // no WriteHeader was called so it will be set to StatusOK in actual ResponseWriter
	}

	// send actual data
	num, err := w.ResponseWriter.Write(b)

	// copy data sent
	if w.copyData {
		if w.data == nil {
			w.data = make([]byte, num)
			copy(w.data, b[:num])
		} else {
			w.data = append(w.data, b[:num]...)
		}
	}

	// count how many bytes we sent
	w.dataLength += int64(num)

	return num, err
}

func (w *customResponseWriter) WriteHeader(statusCode int) {
	w.responseSent = true
	w.statusCodeSent = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *customResponseWriter) getHttpResponse(r *http.Request) *http.Response {
	// craft response on the fly for analytics
	httpResponse := &http.Response{
		Status:        http.StatusText(w.statusCodeSent),
		StatusCode:    w.statusCodeSent,
		Header:        w.ResponseWriter.Header(), // TODO: worth to think about trailer headers
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Request:       r,
		ContentLength: w.dataLength,
	}
	if w.copyData {
		httpResponse.Body = ioutil.NopCloser(bytes.NewReader(w.data))
	}

	return httpResponse
}

// GoPluginMiddleware is a generic middleware that will execute Go-plugin code before continuing
type GoPluginMiddleware struct {
	BaseMiddleware
	Path           string // path to .so file
	SymbolName     string // function symbol to look up
	handler        http.HandlerFunc
	logger         *logrus.Entry
	successHandler *SuccessHandler // to record analytics
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

	// to record 2XX hits in analytics
	m.successHandler = &SuccessHandler{BaseMiddleware: m.BaseMiddleware}

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

	// make sure request's body can be re-read again
	nopCloseRequestBody(r)

	// wrap ResponseWriter to check if response was sent
	rw := &customResponseWriter{
		ResponseWriter: w,
		copyData:       recordDetail(r, m.Spec),
	}

	// call Go-plugin function
	t1 := time.Now()

	// Inject definition into request context:
	ctx.SetDefinition(r, m.Spec.APIDefinition)

	m.handler(rw, r)

	// calculate latency
	ms := DurationToMillisecond(time.Since(t1))
	m.logger.WithField("ms", ms).Debug("Go-plugin request processing took")

	// check if response was sent
	if rw.responseSent {
		// check if response code was an error one
		switch {
		case rw.statusCodeSent == http.StatusForbidden:
			m.logger.WithError(err).Error("Authentication error in Go-plugin middleware func")
			m.Base().FireEvent(EventAuthFailure, EventKeyFailureMeta{
				EventMetaDefault: EventMetaDefault{Message: "Auth Failure", OriginatingRequest: EncodeRequestToEvent(r)},
				Path:             r.URL.Path,
				Origin:           request.RealIP(r),
				Key:              "n/a",
			})
			fallthrough
		case rw.statusCodeSent >= http.StatusBadRequest:
			// base middleware will report this error to analytics if needed
			respCode = rw.statusCodeSent
			err = fmt.Errorf("plugin function sent error response code: %d", rw.statusCodeSent)
			m.logger.WithError(err).Error("Failed to process request with Go-plugin middleware func")
		default:
			// record 2XX to analytics
			m.successHandler.RecordHit(r, Latency{Total: int64(ms)}, rw.statusCodeSent, rw.getHttpResponse(r))

			// no need to continue passing this request down to reverse proxy
			respCode = mwStatusRespond
		}
	} else {
		respCode = http.StatusOK
	}

	return
}
