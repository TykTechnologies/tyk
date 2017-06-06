// +build !coprocess

package main

import (
	"net/http"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
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
	*TykMiddleware
	HookType         coprocess.HookType
	HookName         string
	MiddlewareDriver apidef.MiddlewareDriver
}

func (m *CoProcessMiddleware) GetName() string {
	return "CoProcessMiddlewareDummy"
}

func (m *CoProcessMiddleware) IsEnabledForSpec() bool { return false }
func (m *CoProcessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	return nil, 200
}

type CoProcessEventHandler JSVMEventHandler

func (l CoProcessEventHandler) New(handlerConf interface{}) (TykEventHandler, error) {
	return nil, nil
}

func CoProcessInit() {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Info("Disabled feature")
}

func doCoprocessReload() {}

func newExtractor(referenceSpec *APISpec, mw *TykMiddleware) {}
