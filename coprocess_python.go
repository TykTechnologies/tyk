// +build coprocess
// +build python

package main

/*
#cgo pkg-config: python3
#cgo python CFLAGS: -DENABLE_PYTHON -DPy_LIMITED_API


#include <Python.h>

#include <stdio.h>
#include <stdlib.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#include "coprocess/python/binding.h"
#include "coprocess/python/dispatcher.h"

#include "coprocess/python/tyk/gateway_wrapper.h"

PyGILState_STATE gilState;

static int Python_Init() {
	CoProcessLog( sdsnew("Initializing interpreter, Py_Initialize()"), "info");
	// This exposes the glue module as "gateway_wrapper"
	PyImport_AppendInittab("gateway_wrapper", &PyInit_gateway_wrapper);
	Py_Initialize();
	gilState = PyGILState_Ensure();
	PyEval_InitThreads();
	return Py_IsInitialized();
}


static int Python_LoadDispatcher() {
	PyObject *module_name = PyUnicode_FromString( dispatcher_module_name );
	dispatcher_module = PyImport_Import( module_name );

	if( dispatcher_module == NULL ) {
		PyErr_Print();
		return -1;
	}

	dispatcher_module_dict = PyModule_GetDict(dispatcher_module);

	if( dispatcher_module_dict == NULL ) {
		PyErr_Print();
		return -1;
	}

	dispatcher_class = PyDict_GetItemString(dispatcher_module_dict, dispatcher_class_name);

	if( dispatcher_class == NULL ) {
		PyErr_Print();
		return -1;
	}

	return 0;
}

static void Python_ReloadDispatcher() {
	gilState = PyGILState_Ensure();
	PyObject *hook_name = PyUnicode_FromString(dispatcher_reload);
	if( dispatcher_reload_hook == NULL ) {
		dispatcher_reload_hook = PyObject_GetAttr(dispatcher, hook_name);
	};

	PyObject* result = PyObject_CallObject( dispatcher_reload_hook, NULL );

	PyGILState_Release(gilState);

}

static void Python_HandleMiddlewareCache(char* bundle_path) {
	gilState = PyGILState_Ensure();
	if( PyCallable_Check(dispatcher_load_bundle) ) {
		PyObject* load_bundle_args = PyTuple_Pack( 1, PyUnicode_FromString(bundle_path) );
		PyObject_CallObject( dispatcher_load_bundle, load_bundle_args );
	}
	PyGILState_Release(gilState);
}

static int Python_NewDispatcher(char* middleware_path, char* event_handler_path, char* bundle_paths) {
	PyThreadState*  mainThreadState = PyEval_SaveThread();
	gilState = PyGILState_Ensure();
	if( PyCallable_Check(dispatcher_class) ) {
		dispatcher_args = PyTuple_Pack( 3, PyUnicode_FromString(middleware_path), PyUnicode_FromString(event_handler_path), PyUnicode_FromString(bundle_paths) );
		dispatcher = PyObject_CallObject( dispatcher_class, dispatcher_args );

		if( dispatcher == NULL) {
			PyErr_Print();
			PyGILState_Release(gilState);
			return -1;
		}
	} else {
		PyErr_Print();
		PyGILState_Release(gilState);
		return -1;
	}

	dispatcher_hook_name = PyUnicode_FromString( hook_name );
	dispatcher_hook = PyObject_GetAttr(dispatcher, dispatcher_hook_name);

	dispatch_event_name = PyUnicode_FromString( dispatch_event_name_s );
	dispatch_event = PyObject_GetAttr(dispatcher, dispatch_event_name );

	dispatcher_load_bundle_name = PyUnicode_FromString( load_bundle_name );
	dispatcher_load_bundle = PyObject_GetAttr(dispatcher, dispatcher_load_bundle_name);

	if( dispatcher_hook == NULL ) {
		PyErr_Print();
		PyGILState_Release(gilState);
		return -1;
	}
	PyGILState_Release(gilState);
	return 0;
}

static void Python_SetEnv(char* python_path) {
	CoProcessLog( sdscatprintf(sdsempty(), "Setting PYTHONPATH to '%s'", python_path), "info");
	setenv("PYTHONPATH", python_path, 1 );
}

static struct CoProcessMessage* Python_DispatchHook(struct CoProcessMessage* object) {
	struct CoProcessMessage* outputObject = malloc(sizeof *outputObject);

	if (object->p_data == NULL) {
		return outputObject;
	}

	gilState = PyGILState_Ensure();
	PyObject *args = PyTuple_Pack( 1, PyBytes_FromStringAndSize(object->p_data, object->length) );

	PyObject *result = PyObject_CallObject( dispatcher_hook, args );

	if( result == NULL ) {
		PyErr_Print();
	} else {
		PyObject* new_object_msg_item = PyTuple_GetItem( result, 0 );
		char* output = PyBytes_AsString(new_object_msg_item);

		PyObject* new_object_msg_length = PyTuple_GetItem( result, 1 );
		int msg_length = PyLong_AsLong(new_object_msg_length);

		outputObject->p_data = (void*)output;
		outputObject->length = msg_length;
	}

	PyGILState_Release(gilState);

	return outputObject;
}

static void Python_DispatchEvent(char* event_json) {
	gilState = PyGILState_Ensure();
	PyObject *args = PyTuple_Pack( 1, PyUnicode_FromString(event_json) );
	PyObject *result = PyObject_CallObject( dispatch_event, args );
	PyGILState_Release(gilState);
}

*/
import "C"

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
)

// CoProcessName declares the driver name.
const CoProcessName = apidef.PythonDriver

// MessageType sets the default message type.
var MessageType = coprocess.ProtobufMessage

// PythonDispatcher implements a coprocess.Dispatcher
type PythonDispatcher struct {
	coprocess.Dispatcher
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *PythonDispatcher) Dispatch(objectPtr unsafe.Pointer) unsafe.Pointer {
	object := (*C.struct_CoProcessMessage)(objectPtr)
	newObjectPtr := C.Python_DispatchHook(object)
	return unsafe.Pointer(newObjectPtr)
}

// DispatchEvent dispatches a Tyk event.
func (d *PythonDispatcher) DispatchEvent(eventJSON []byte) {
	CEventJSON := C.CString(string(eventJSON))
	C.Python_DispatchEvent(CEventJSON)
	C.free(unsafe.Pointer(CEventJSON))
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *PythonDispatcher) Reload() {
	C.Python_ReloadDispatcher()
}

// HandleMiddlewareCache isn't used by Python.
func (d *PythonDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {
	done := make(chan bool)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		CBundlePath := C.CString(basePath)
		C.Python_HandleMiddlewareCache(CBundlePath)
		done <- true
	}()
	<-done
}

// PythonInit initializes the Python interpreter.
func PythonInit() error {
	result := C.Python_Init()
	if result == 0 {
		return errors.New("Can't Py_Initialize()")
	}
	return nil
}

// PythonLoadDispatcher creates reference to the dispatcher class.
func PythonLoadDispatcher() error {
	result := C.Python_LoadDispatcher()
	if result == -1 {
		return errors.New("Can't load dispatcher")
	}
	return nil
}

// PythonNewDispatcher creates an instance of TykDispatcher.
func PythonNewDispatcher(middlewarePath, eventHandlerPath string, bundlePaths []string) (coprocess.Dispatcher, error) {
	CMiddlewarePath := C.CString(middlewarePath)
	CEventHandlerPath := C.CString(eventHandlerPath)
	CBundlePaths := C.CString(strings.Join(bundlePaths, ":"))

	result := C.Python_NewDispatcher(CMiddlewarePath, CEventHandlerPath, CBundlePaths)
	if result == -1 {
		return nil, errors.New("can't initialize a dispatcher")
	}

	dispatcher := &PythonDispatcher{}

	C.free(unsafe.Pointer(CMiddlewarePath))
	C.free(unsafe.Pointer(CEventHandlerPath))

	return dispatcher, nil
}

// PythonSetEnv sets PYTHONPATH, it's called before initializing the interpreter.
func PythonSetEnv(pythonPaths ...string) {
	CPythonPath := C.CString(strings.Join(pythonPaths, ":"))
	C.Python_SetEnv(CPythonPath)
	C.free(unsafe.Pointer(CPythonPath))
}

// getBundlePaths will return an array of the available bundle directories:
func getBundlePaths() []string {
	bundlePath := filepath.Join(config.Global.MiddlewarePath, "bundles")
	directories := make([]string, 0)
	bundles, _ := ioutil.ReadDir(bundlePath)
	for _, f := range bundles {
		if f.IsDir() {
			fullPath := filepath.Join(bundlePath, f.Name())
			directories = append(directories, fullPath)
		}
	}
	return directories
}

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (dispatcher coprocess.Dispatcher, err error) {
	workDir := config.Global.CoProcessOptions.PythonPathPrefix

	dispatcherPath := filepath.Join(workDir, "coprocess", "python")
	middlewarePath := filepath.Join(workDir, "middleware", "python")
	eventHandlerPath := filepath.Join(workDir, "event_handlers")
	protoPath := filepath.Join(workDir, "coprocess", "python", "proto")

	paths := []string{dispatcherPath, middlewarePath, eventHandlerPath, protoPath}

	// Append bundle paths:
	bundlePaths := getBundlePaths()
	for _, v := range bundlePaths {
		paths = append(paths, v)
	}

	// initDone is used to signal the end of Python initialization step:
	initDone := make(chan error)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		PythonSetEnv(paths...)
		PythonInit()
		PythonLoadDispatcher()
		dispatcher, err = PythonNewDispatcher(middlewarePath, eventHandlerPath, bundlePaths)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "coprocess",
			}).Error(err)
		}
		initDone <- err
	}()
	err = <-initDone
	return dispatcher, err
}
