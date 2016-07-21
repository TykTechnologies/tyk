// +build coprocess

package main

/*
#include <stdio.h>

#include "coprocess/sds/sds.h"

#include "coprocess/python/dispatcher.h"
#include "coprocess/python/binding.h"

extern void CoProcess_Log(char *msg, char *level);

*/
import "C"

import (
	"github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"

	"encoding/json"

	"bytes"
	"io/ioutil"
	"net/http"
)

var EnableCoProcess bool = true

var GlobalDispatcher CoProcessDispatcher

func CoProcessDispatchHook(r CoProcessMiniRequestObject, payloadType string) CoProcessMiniRequestObject {
	payload, _ := json.Marshal(r)
	return GlobalDispatcher.DispatchHook(string(payload), payloadType)
}

func CreateCoProcessMiddleware(MiddlewareName string, IsPre, UseSession bool, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &CoProcessMiddleware{
		TykMiddleware:       tykMwSuper,
		MiddlewareClassName: MiddlewareName,
		Pre:                 IsPre,
		UseSession:          UseSession,
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

type CoProcessDispatcher interface {
	DispatchHook(string, string) CoProcessMiniRequestObject
}

type CoProcessMiniRequestObject struct {
	Headers         map[string][]string
	SetHeaders      map[string]string
	DeleteHeaders   []string
	Body            string
	URL             string
	Params          map[string][]string
	AddParams       map[string]string
	ExtendedParams  map[string][]string
	DeleteParams    []string
	ReturnOverrides ReturnOverrides
}

type CoProcessMiddleware struct {
	*TykMiddleware
	MiddlewareClassName string
	Pre                 bool
	UseSession          bool
}

type CoProcessMiddlewareConfig struct {
	ConfigData map[string]string `mapstructure:"config_data" bson:"config_data" json:"config_data"`
}

// New lets you do any initialisations for the object can be done here
func (m *CoProcessMiddleware) New() {}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (m *CoProcessMiddleware) GetConfig() (interface{}, error) {
	var thisModuleConfig CoProcessMiddlewareConfig

	err := mapstructure.Decode(m.TykMiddleware.Spec.APIDefinition.RawData, &thisModuleConfig)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "jsvm",
		}).Error(err)
		return nil, err
	}

	return thisModuleConfig, nil
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *CoProcessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	/*
	  log.WithFields(logrus.Fields{
	    "prefix": "CoProcessMiddleware",
	  }).Info( "ProcessRequest: ", m.MiddlewareClassName )
	*/

	defer r.Body.Close()
	originalBody, _ := ioutil.ReadAll(r.Body)

	var thisRequestData, newRequestData CoProcessMiniRequestObject

	thisRequestData = CoProcessMiniRequestObject{
		Headers:        r.Header,
		SetHeaders:     make(map[string]string),
		DeleteHeaders:  make([]string, 0),
		Body:           string(originalBody),
		URL:            r.URL.Path,
		Params:         r.URL.Query(),
		AddParams:      make(map[string]string),
		ExtendedParams: make(map[string][]string),
		DeleteParams:   make([]string, 0),
	}

	if m.Pre {
		newRequestData = CoProcessDispatchHook(thisRequestData, "pre")
		r.ContentLength = int64(len(newRequestData.Body))
		r.Body = ioutil.NopCloser(bytes.NewBufferString(newRequestData.Body))

		for h, v := range newRequestData.SetHeaders {
			r.Header.Set(h, v)
		}

	} else {
		// CoProcessDispatchHook(thisRequestData, "post")
		r.Body = ioutil.NopCloser(bytes.NewBuffer(originalBody))
	}

	log.Println("thisRequestData:", thisRequestData)
	log.Println("newRequestData::", newRequestData)

	return nil, 200
}

//export CoProcess_Log
func CoProcess_Log(CMessage *C.char, CLogLevel *C.char) {
	var message, logLevel string
	message = C.GoString(CMessage)
	logLevel = C.GoString(CLogLevel)

	switch logLevel {
	case "error":
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Error(message)
	default:
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Info(message)
	}
}
