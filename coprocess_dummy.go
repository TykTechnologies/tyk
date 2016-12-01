// +build !coprocess

package main

import (
	"github.com/TykTechnologies/logrus"

	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tykcommon"

	"net/http"
)

const (
	EH_CoProcessHandler tykcommon.TykEventHandlerName = "cp_dynamic_handler"
)

type Dispatcher interface {
	DispatchEvent([]byte)
	LoadModules()
	HandleMiddlewareCache(*tykcommon.BundleManifest, string)
	Reload()
}


var GlobalDispatcher Dispatcher

var EnableCoProcess bool = false

type CoProcessMiddleware struct {
	*TykMiddleware
	HookType         coprocess.HookType
	HookName         string
	MiddlewareDriver tykcommon.MiddlewareDriver
}

func (m *CoProcessMiddleware) New() {}

func (a *CoProcessMiddleware) IsEnabledForSpec() bool {
	return false
}

func (m *CoProcessMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

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
	return
}

func doCoprocessReload() {
	return
}

func newExtractor(referenceSpec *APISpec, mw *TykMiddleware) {
}
