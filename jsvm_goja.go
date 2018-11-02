package main

import (
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	_ "github.com/robertkrimen/otto/underscore"
)

type TykJSVM interface {
	Init(spec *APISpec, logger *logrus.Entry)
	LoadJSPaths(paths []string, prefix string)
	LoadTykJSApi()
	RunJSRequestDynamic(d *DynamicMiddleware, logger *logrus.Entry, requestAsJson string, sessionAsJson string, specAsJson string) (error, int, string)
	RunJSRequestVirtual(d *VirtualEndpoint, logger *logrus.Entry, vmeta *apidef.VirtualMeta, requestAsJson string, sessionAsJson string, specAsJson string) (error, int, string)
	Run(s string) (interface{}, error)
	GetLog() *logrus.Entry
	GetRawLog() *logrus.Logger
	GetTimeout() time.Duration
}

func InitJSVM() TykJSVM {
	jsvm := &OttoJSVM{}

	switch config.Global().JSVM {
	case "goja":
	default:
	}
	return jsvm
}
