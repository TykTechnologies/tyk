// +build coprocess

package main

/*
#include <stdio.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#include "coprocess/python/dispatcher.h"
#include "coprocess/python/binding.h"

*/
import "C"

import (
	"github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"
	// "github.com/gorilla/context"

	"github.com/TykTechnologies/tykcommon/coprocess"

	"encoding/json"

	// "bytes"
	"io/ioutil"
	"net/http"
)

var EnableCoProcess bool = true

var GlobalDispatcher CoProcessDispatcher

func CoProcessDispatchHook(o CoProcessObject) CoProcessObject {
	objectAsJson, _ := json.Marshal(o)
	return GlobalDispatcher.DispatchHook(objectAsJson)
}

func CreateCoProcessMiddleware(hookType int, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &CoProcessMiddleware{
		TykMiddleware:       tykMwSuper,
		HookType: hookType,
		/*
		MiddlewareClassName: MiddlewareName,
		UseSession:          UseSession,
		*/
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

type CoProcessor struct {
	HookType string
}

func( c *CoProcessor ) SetHookType(hookType string) {
	c.HookType = hookType
}

func( c *CoProcessor ) GetObjectFromRequest(r *http.Request ) CoProcessObject {

	defer r.Body.Close()
	originalBody, _ := ioutil.ReadAll(r.Body)

	var object CoProcessObject

	object.Request = CoProcessMiniRequestObject{
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

	return object
}

func( c *CoProcessor ) Dispatch(object *CoProcessObject) CoProcessObject {

	 objectJson, _ := json.Marshal(object)

	 var CObjectStr *C.char
	 CObjectStr = C.CString(string(objectJson))

	 log.Println("Cobjectstr", CObjectStr)

	 var CNewObjectStr *C.char
	 CNewObjectStr = GlobalDispatcher.Dispatch(CObjectStr)

	 var newObjectStr string
	 newObjectStr = C.GoString(CNewObjectStr)

	 log.Println("Got CNewObjectStr: ", newObjectStr)

	 return CoProcessObject{}
}

type CoProcessDispatcher interface {
	DispatchHook([]byte) CoProcessObject
	Dispatch(*C.char) *C.char
}

type CoProcessObject struct {
	HookType string	`json:"hook_type"`
	Request CoProcessMiniRequestObject	`json:"request,omitempty"`
	Session SessionState	`json:"session,omitempty"`
	Spec map[string]string `json:"spec,omitempty"`
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
	HookType int
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
	  log.WithFields(logrus.Fields{
	    "prefix": "coprocess",
	  }).Info( "ProcessRequest, HookType:", m.HookType )

	thisCoProcessor := CoProcessor{}

	switch m.HookType {
	case coprocess.PreHook:
		thisCoProcessor.SetHookType("pre")
	case coprocess.PostHook:
		thisCoProcessor.SetHookType("post")
	case coprocess.PostKeyAuthHook:
		thisCoProcessor.SetHookType("postkeyauth")
	default:
		thisCoProcessor.SetHookType("")
	}

	object := thisCoProcessor.GetObjectFromRequest(r)

	log.Println("GetObjectFromRequest =", object)

	returnObject := thisCoProcessor.Dispatch(&object)

	log.Println("returnObject =", returnObject)

	/*

	defer r.Body.Close()
	originalBody, _ := ioutil.ReadAll(r.Body)

	var object, newObject CoProcessObject

	object.Request = CoProcessMiniRequestObject{
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

	switch m.HookType {
	case coprocess.PreHook:
		object.HookType = "pre"
	case coprocess.PostHook:
		object.HookType = "post"
	case coprocess.PostKeyAuthHook:
		object.HookType = "postkeyauth"
	default:
		object.HookType = ""
	}

	// Encode the session object (if not a pre-process)
	if m.HookType != coprocess.PreHook  && m.HookType != coprocess.CustomKeyCheckHook {
		var session interface{}
		session = context.Get(r, SessionData)
		if session != nil {
			object.Session = session.(SessionState)
		}
	}

	// Append spec data
	object.Spec = map[string]string{
		"OrgID": m.TykMiddleware.Spec.OrgID,
		"APIID": m.TykMiddleware.Spec.APIID,
	}

	newObject = CoProcessDispatchHook(object)

	r.ContentLength = int64(len(newObject.Request.Body))
	r.Body = ioutil.NopCloser(bytes.NewBufferString(newObject.Request.Body))

	for _, dh := range newObject.Request.DeleteHeaders {
		r.Header.Del(dh)
	}

	for h, v := range newObject.Request.SetHeaders {
		r.Header.Set(h, v)
	}

	values := r.URL.Query()
	for _, k := range newObject.Request.DeleteParams {
		values.Del(k)
	}

	for p, v := range newObject.Request.AddParams {
		values.Set(p, v)
	}

	r.URL.RawQuery = values.Encode()
	*/

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
