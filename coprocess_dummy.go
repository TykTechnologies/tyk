// +build !coprocess

package main

import (
	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tykcommon"

	"net/http"
)

const (
	EH_CoProcessHandler tykcommon.TykEventHandlerName = "cp_dynamic_handler"
)

var EnableCoProcess bool = false

type DummyCoProcessMiddleware struct {
	*TykMiddleware
}

func (m *DummyCoProcessMiddleware) New() {}

func (a *DummyCoProcessMiddleware) IsEnabledForSpec() bool {
	return false
}

func (m *DummyCoProcessMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (m *DummyCoProcessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
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

func CreateCoProcessMiddleware(MiddlewareName string, hookType coprocess.HookType, mwDriver tykcommon.MiddlewareDriver, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	return CreateMiddleware(&DummyCoProcessMiddleware{tykMwSuper}, tykMwSuper)
}

type IdExtractorMiddleware struct {
	*TykMiddleware
}

func (m *IdExtractorMiddleware) New() {}
func (m *IdExtractorMiddleware) GetConfig() (interface{}, error) { return nil, nil }
func (m *IdExtractorMiddleware) IsEnabledForSpec() bool { return false }
func (m *IdExtractorMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	return nil, 200
}

func CreateIdExtractorMiddleware(mwDriver tykcommon.MiddlewareDriver, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	return CreateMiddleware(&DummyCoProcessMiddleware{tykMwSuper}, tykMwSuper)
}
