// +build coprocess

//go:generate msgp
//msgp:ignore CoProcessor CoProcessMiddleware CoProcessMiddlewareConfig TykMiddleware

package main

/*
#cgo python CFLAGS: -DENABLE_PYTHON
#include <stdio.h>
#include <stdlib.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#ifdef ENABLE_PYTHON
#include "coprocess/python/dispatcher.h"
#include "coprocess/python/binding.h"
#endif

*/
import "C"

import (
	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"
	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/TykTechnologies/tykcommon"

	"encoding/json"
	"github.com/golang/protobuf/proto"

	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"unsafe"
)

// EnableCoProcess will be overridden by config.EnableCoProcess.
var EnableCoProcess = false

// GlobalDispatcher will be implemented by the current CoProcess driver.
var GlobalDispatcher coprocess.Dispatcher

// CoProcessMiddleware is the basic CP middleware struct.
type CoProcessMiddleware struct {
	*TykMiddleware
	HookType         coprocess.HookType
	HookName         string
	MiddlewareDriver tykcommon.MiddlewareDriver
}

// CreateCoProcessMiddleware initializes a new CP middleware, takes hook type (pre, post, etc.), hook name ("my_hook") and driver ("python").
func CreateCoProcessMiddleware(hookName string, hookType coprocess.HookType, mwDriver tykcommon.MiddlewareDriver, tykMwSuper *TykMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &CoProcessMiddleware{
		TykMiddleware:    tykMwSuper,
		HookType:         hookType,
		HookName:         hookName,
		MiddlewareDriver: mwDriver,
	}

	return CreateMiddleware(dMiddleware, tykMwSuper)
}

func doCoprocessReload() {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Info("Reloading middlewares")
	GlobalDispatcher.Reload()

}

// CoProcessor represents a CoProcess during the request.
type CoProcessor struct {
	HookType   coprocess.HookType
	Middleware *CoProcessMiddleware
}

// GetObjectFromRequest constructs a CoProcessObject from a given http.Request.
func (c *CoProcessor) GetObjectFromRequest(r *http.Request) *coprocess.Object {

	defer r.Body.Close()
	originalBody, _ := ioutil.ReadAll(r.Body)

	var object *coprocess.Object
	var miniRequestObject *coprocess.MiniRequestObject

	miniRequestObject = &coprocess.MiniRequestObject{
		Headers:         ProtoMap(r.Header),
		SetHeaders:      make(map[string]string, 0),
		DeleteHeaders:   make([]string, 0),
		Body:            string(originalBody),
		Url:             r.URL.Path,
		Params:          ProtoMap(r.URL.Query()),
		AddParams:       make(map[string]string),
		ExtendedParams:  ProtoMap(nil),
		DeleteParams:    make([]string, 0),
		ReturnOverrides: &coprocess.ReturnOverrides{-1, ""},
	}

	object = &coprocess.Object{
		Request:  miniRequestObject,
		HookName: c.Middleware.HookName,
	}

	// If a middleware is set, take its HookType, otherwise override it with CoProcessor.HookType
	if c.Middleware != nil && c.HookType == 0 {
		c.HookType = c.Middleware.HookType
	}

	object.HookType = c.HookType

	object.Metadata = make(map[string]string, 0)
	object.Spec = make(map[string]string, 0)

	// object.Session = SessionState{}

	// Append spec data:
	if c.Middleware != nil {
		object.Spec = map[string]string{
			"OrgID": c.Middleware.TykMiddleware.Spec.OrgID,
			"APIID": c.Middleware.TykMiddleware.Spec.APIID,
		}
	}

	// Encode the session object (if not a pre-process & not a custom key check):
	if c.HookType != coprocess.HookType_Pre && c.HookType != coprocess.HookType_CustomKeyCheck {
		var session interface{}
		session = context.Get(r, SessionData)
		if session != nil {
			sessionState := session.(SessionState)
			object.Session = ProtoSessionState(sessionState)
		}
	}

	return object
}

// ObjectPostProcess does CoProcessObject post-processing (adding/removing headers or params, etc.).
func (c *CoProcessor) ObjectPostProcess(object *coprocess.Object, r *http.Request) {
	r.ContentLength = int64(len(object.Request.Body))
	r.Body = ioutil.NopCloser(bytes.NewBufferString(object.Request.Body))

	for _, dh := range object.Request.DeleteHeaders {
		r.Header.Del(dh)
	}

	for h, v := range object.Request.SetHeaders {
		r.Header.Set(h, v)
	}

	values := r.URL.Query()
	for _, k := range object.Request.DeleteParams {
		values.Del(k)
	}

	for p, v := range object.Request.AddParams {
		values.Set(p, v)
	}

	r.URL.RawQuery = values.Encode()
}

// Dispatch prepares a CoProcessMessage, sends it to the GlobalDispatcher and gets a reply.
func (c *CoProcessor) Dispatch(object *coprocess.Object) *coprocess.Object {

	var objectMsg []byte

	if MessageType == coprocess.ProtobufMessage {
		objectMsg, _ = proto.Marshal(object)
	} else if MessageType == coprocess.JsonMessage {
		objectMsg, _ = json.Marshal(object)
	}

	if CoProcessName == "grpc" {
		object = GlobalDispatcher.DispatchObject(object)
		return object
	}

	objectMsgStr := string(objectMsg)

	var CObjectStr *C.char
	CObjectStr = C.CString(objectMsgStr)

	var objectPtr *C.struct_CoProcessMessage

	objectPtr = (*C.struct_CoProcessMessage)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_CoProcessMessage{}))))
	objectPtr.p_data = unsafe.Pointer(CObjectStr)
	objectPtr.length = C.int(len(objectMsg))

	var newObjectPtr *C.struct_CoProcessMessage
	newObjectPtr = (*C.struct_CoProcessMessage)(GlobalDispatcher.Dispatch(unsafe.Pointer(objectPtr)))

	var newObjectBytes []byte
	newObjectBytes = C.GoBytes(newObjectPtr.p_data, newObjectPtr.length)

	newObject := &coprocess.Object{}

	if MessageType == coprocess.ProtobufMessage {
		proto.Unmarshal(newObjectBytes, newObject)
	} else if MessageType == coprocess.JsonMessage {
		json.Unmarshal(newObjectBytes, newObject)
	}

	C.free(unsafe.Pointer(CObjectStr))
	C.free(unsafe.Pointer(objectPtr))
	C.free(unsafe.Pointer(newObjectPtr))

	return newObject
}

// CoProcessInit creates a new CoProcessDispatcher, it will be called when Tyk starts.
func CoProcessInit() (err error) {
	if config.CoProcessOptions.EnableCoProcess {
		GlobalDispatcher, err = NewCoProcessDispatcher()
		EnableCoProcess = true
	}
	return err
}

// CoProcessMiddlewareConfig holds the middleware configuration.
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

func (m *CoProcessMiddleware) IsEnabledForSpec() bool {
	return true
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (m *CoProcessMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Debug("CoProcess Request, HookType: ", m.HookType)

	if !EnableCoProcess {
		return nil, 200
	}

	// It's also possible to override the HookType:
	thisCoProcessor := CoProcessor{
		Middleware: m,
		// HookType: coprocess.PreHook,
	}

	object := thisCoProcessor.GetObjectFromRequest(r)

	returnObject := thisCoProcessor.Dispatch(object)

	thisCoProcessor.ObjectPostProcess(returnObject, r)

	authHeaderValue := returnObject.Metadata["token"]

	if returnObject.Request.ReturnOverrides.ResponseCode > 400 {

		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    authHeaderValue,
		}).Info("Attempted access with invalid key.")

		// Fire Authfailed Event
		AuthFailed(m.TykMiddleware, r, authHeaderValue)

		// Report in health check
		ReportHealthCheckValue(m.Spec.Health, KeyFailure, "1")

		return errors.New("Key not authorised"), int(returnObject.Request.ReturnOverrides.ResponseCode)
	}

	if m.HookType == coprocess.HookType_CustomKeyCheck {
		if returnObject.Session != nil {
			// context.Set(r, SessionData, ToTykSession(returnObject.Session))
			context.Set(r, SessionData, TykSessionState(returnObject.Session))
			context.Set(r, AuthHeaderValue, authHeaderValue)
		}
	}

	// context.GetOk(r, SessionData)

	return nil, 200
}

// CoProcessLog is a bridge for using Tyk log from CP.
//export CoProcessLog
func CoProcessLog(CMessage *C.char, CLogLevel *C.char) {
	var message, logLevel string
	message = C.GoString(CMessage)
	logLevel = C.GoString(CLogLevel)

	switch logLevel {
	case "debug":
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Debug(message)
	case "error":
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Error(message)
	case "warning":
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Warning(message)
	default:
		log.WithFields(logrus.Fields{
			"prefix": CoProcessName,
		}).Info(message)
	}
}
