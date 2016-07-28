// +build !coprocess

package main

import (
	"github.com/Sirupsen/logrus"
	"net/http"
)

var EnableCoProcess bool = false

const(
	_ = iota
	CoProcessPre
	CoProcessPost
	CoProcessPostKeyAuth
)

func CoProcessInit() {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Info("Disabled feature")
}

func CreateCoProcessMiddleware(hookType int, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	return nil
}
