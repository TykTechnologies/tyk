package gateway

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/goplugin"
	"github.com/TykTechnologies/tyk/request"
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

func (w *customResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
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
	Meta           apidef.GoPluginMeta
	APILevel       bool
}

func (m *GoPluginMiddleware) Name() string {
	return "GoPluginMiddleware: " + m.Path + ":" + m.SymbolName
}

func (m *GoPluginMiddleware) EnabledForSpec() bool {
	// global go plugins
	if m.Path != "" && m.SymbolName != "" {
		m.loadPlugin()
		return true
	}

	// per path go plugins
	for _, version := range m.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.GoPlugin) > 0 {
			return true
		}
	}

	return false
}

// loadPlugin loads the plugin file from m.Path, it will try
//converting it to the tyk version aware format: {plugin_name}_{tyk_version}_{os}_{arch}.so
// if the file doesn't exist then it will again but with a gw version that is not prefixed by 'v'
// later, it will try with m.path which can be {plugin_name}.so
func (m *GoPluginMiddleware) loadPlugin() bool {
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

	newPath, err := goplugin.GetPluginFileNameToLoad(m.Path, VERSION)
	if err != nil {
		m.logger.WithError(err).Error("plugin file not found")
		return false
	}
	if m.Path != newPath {
		m.Path = newPath
	}

	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
			m.logger.WithError(err).Error("Recovered from panic while loading Go-plugin")
		}
	}()

	if m.handler, err = goplugin.GetHandler(m.Path, m.SymbolName); err != nil {
		m.logger.WithError(err).Error("Could not load Go-plugin")
		return false
	}

	// to record 2XX hits in analytics
	m.successHandler = &SuccessHandler{BaseMiddleware: m.BaseMiddleware}
	return true
}

func (m *GoPluginMiddleware) goPluginFromRequest(r *http.Request) (*GoPluginMiddleware, bool) {
	version, _ := m.Spec.Version(r)
	versionPaths := m.Spec.RxPaths[version.Name]

	found, perPathPerMethodGoPlugin := m.Spec.CheckSpecMatchesStatus(r, versionPaths, GoPlugin)
	if !found {
		return nil, false
	}
	return perPathPerMethodGoPlugin.(*GoPluginMiddleware), found
}
func (m *GoPluginMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (err error, respCode int) {
	// if a Go plugin is found for this path, override the base handler and logger:
	logger := m.logger
	handler := m.handler
	if !m.APILevel {
		if pluginMw, found := m.goPluginFromRequest(r); found {
			logger = pluginMw.logger
			handler = pluginMw.handler
		}
	}
	if handler == nil {
		return
	}

	// make sure tyk recover in case Go-plugin function panics
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
			respCode = http.StatusInternalServerError
			logger.WithError(err).Error("Recovered from panic while running Go-plugin middleware func")
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
	handler(rw, r)

	// calculate latency
	ms := DurationToMillisecond(time.Since(t1))
	logger.WithField("ms", ms).Debug("Go-plugin request processing took")

	// check if response was sent
	if rw.responseSent {
		// check if response code was an error one
		switch {
		case rw.statusCodeSent == http.StatusForbidden:
			logger.WithError(err).Error("Authentication error in Go-plugin middleware func")
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
			logger.WithError(err).Error("Failed to process request with Go-plugin middleware func")
		default:
			// record 2XX to analytics
			m.successHandler.RecordHit(r, analytics.Latency{Total: int64(ms)}, rw.statusCodeSent, rw.getHttpResponse(r))

			// no need to continue passing this request down to reverse proxy
			respCode = mwStatusRespond
		}
	} else {
		respCode = http.StatusOK
	}

	return
}
