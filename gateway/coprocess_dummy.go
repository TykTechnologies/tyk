// +build !coprocess

package gateway

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tyk/user"
)

const (
	EH_CoProcessHandler apidef.TykEventHandlerName = "cp_dynamic_handler"
)

type Dispatcher interface {
	DispatchEvent([]byte)
	LoadModules()
	HandleMiddlewareCache(*apidef.BundleManifest, string)
	Reload()
}

var (
	GlobalDispatcher Dispatcher
	EnableCoProcess  = false
)

type CoProcessMiddleware struct {
	BaseMiddleware
	HookType         coprocess.HookType
	HookName         string
	MiddlewareDriver apidef.MiddlewareDriver
	RawBodyOnly      bool

	successHandler *SuccessHandler
}

func (m *CoProcessMiddleware) Name() string {
	return "CoProcessMiddlewareDummy"
}

func (m *CoProcessMiddleware) EnabledForSpec() bool { return false }
func (m *CoProcessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	return nil, 200
}

type CoProcessEventHandler struct {
	Spec *APISpec
}

func (l *CoProcessEventHandler) Init(handlerConf interface{}) error {
	return nil
}
func (l *CoProcessEventHandler) HandleEvent(em config.EventMessage) {}

func CoProcessInit() error {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Info("Disabled feature")
	return nil
}
func DoCoprocessReload() {}

type CustomMiddlewareResponseHook struct {
	Spec   *APISpec
	mw     apidef.MiddlewareDefinition
	config HeaderInjectorOptions
}

func (h *CustomMiddlewareResponseHook) Init(mw interface{}, spec *APISpec) error {
	return nil
}

func (h *CustomMiddlewareResponseHook) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *CustomMiddlewareResponseHook) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	return nil
}

func (h *CustomMiddlewareResponseHook) Name() string {
	return ""
}
