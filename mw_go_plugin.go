package main

import (
	"fmt"
	"net/http"
	"plugin"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/goplugin"
	"github.com/TykTechnologies/tyk/user"
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
	Path          string // path to .so file
	SymbolName    string // function symbol to look up
	Pre           bool
	UseSession    bool
	Auth          bool
	mwProcessFunc goplugin.ProcessFunc
	mwAuthFunc    goplugin.AuthFunc
	logger        *logrus.Entry
}

func (m *GoPluginMiddleware) Name() string {
	return "GoPluginMiddleware: " + m.Path + ":" + m.SymbolName
}

func (m *GoPluginMiddleware) EnabledForSpec() bool {
	m.logger = log.WithFields(logrus.Fields{
		"mwPath":       m.Path,
		"mwSymbolName": m.SymbolName,
		"isAuth":       m.Auth,
	})

	if m.mwProcessFunc != nil || m.mwAuthFunc != nil {
		m.logger.Info("Go-plugin middleware is already initialized")
		return true
	}

	// try to load plugin
	loadedPlugin, err := plugin.Open(m.Path)
	if err != nil {
		m.logger.WithError(err).Error("Could not load plugin")
		return false
	}

	// try to lookup function symbol
	funcSymbol, err := loadedPlugin.Lookup(m.SymbolName)
	if err != nil {
		m.logger.WithError(err).Error("Could not look up symbol in loaded plugin")
		return false
	}

	// try to cast symbol to real func
	var ok bool
	if m.Auth {
		m.mwAuthFunc, ok = funcSymbol.(func(
			http.ResponseWriter,
			*http.Request,
			goplugin.APISpec,
			goplugin.Logger,
		) (session *user.SessionState, token string, err error))
	} else {
		m.mwProcessFunc, ok = funcSymbol.(func(
			http.ResponseWriter,
			*http.Request,
			*user.SessionState,
			goplugin.APISpec,
			goplugin.Logger,
		) error)
	}
	if !ok {
		m.logger.Error("Could not cast function symbol")
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

	var prevMD5Hash string
	var session *user.SessionState
	if m.UseSession && !m.Pre && !m.Auth { // pass session if requested in meta and it is not auth_check or pre-process
		session = ctxGetSession(r)
		prevMD5Hash = session.MD5Hash()
	}

	apiSpec := goplugin.APISpec{
		OrgID:      m.Spec.OrgID,
		APIID:      m.Spec.APIID,
		ConfigData: m.Spec.ConfigData,
	}

	// make sure request's body can be re-read again
	nopCloseRequestBody(r)

	// wrap ResponseWriter to check if response was sent
	rw := &customResponseWriter{
		ResponseWriter: w,
	}

	// run Go-plugin function
	if m.Auth {
		newSession, token, authErr := m.mwAuthFunc(rw, r, apiSpec, m.logger)
		if authErr != nil {
			err = authErr
		} else {
			// add to context session and token created my custom middleware
			// schedule update so new session will be stored
			ctxSetSession(r, newSession, token, true)
		}
	} else {
		err = m.mwProcessFunc(rw, r, session, apiSpec, m.logger)
		if err == nil {
			// check if session was passed to custom middleware and modified
			if session != nil && prevMD5Hash != session.MD5Hash() {
				ctxScheduleSessionUpdate(r)
			}
		}
	}

	// process returned error
	if err != nil {
		if rw.responseSent {
			respCode = rw.statusCodeSent
		} else {
			m.logger.Warning("Go-plugin func returned error but didn't send response. Forcing 500 status")
			w.WriteHeader(http.StatusInternalServerError)
			respCode = http.StatusInternalServerError
		}
		m.logger.WithError(err).Error("Failed to run Go-plugin middleware func")
		return
	}

	// no errors, check if response was sent
	if rw.responseSent {
		respCode = mwStatusRespond // no need to continue passing this request down to reverse proxy
	} else {
		respCode = http.StatusOK
	}

	return
}
