// +build !coprocess

package main

import (
	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tykcommon"
	"github.com/TykTechnologies/tyk/coprocess"

	"net/http"
)

var EnableCoProcess bool = false

type DummyCoProcessMiddleware struct {
	*TykMiddleware
}

func (m *DummyCoProcessMiddleware) New() {}

func (m *DummyCoProcessMiddleware) GetConfig() (interface{}, error) {
	return nil, nil
}

func (m *DummyCoProcessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	return nil, 200
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
