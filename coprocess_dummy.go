// +build !coprocess

package main

import (
	"github.com/Sirupsen/logrus"

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
}

func CreateCoProcessMiddleware(hookType int, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	return CreateMiddleware(&DummyCoProcessMiddleware{tykMwSuper}, tykMwSuper)
}
