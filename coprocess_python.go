// +build coprocess
// +build python

package main

/*
#cgo pkg-config: python3

#include <Python.h>

#include <stdio.h>
#include <stdlib.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#include "coprocess/python/binding.h"
#include "coprocess/python/dispatcher.h"

#include "coprocess/python/tyk/gateway.h"

PyGILState_STATE gilState;

static int Python_Init() {
  CoProcessLog( sdsnew("Initializing interpreter, Py_Initialize()"), "info");
  Py_Initialize();
	gilState = PyGILState_Ensure();
	PyEval_InitThreads();
	// This exposes the Cython interface as "gateway"
	PyInit_gateway();
  return Py_IsInitialized();
}


static int Python_LoadDispatcher() {
  PyObject *module_name = PyUnicode_FromString( dispatcher_module_name );
  dispatcher_module = PyImport_Import( module_name );

	Py_DECREF(module_name);

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
	PyObject *hook_name = PyUnicode_FromString(dispatcher_reload);
	if( dispatcher_reload_hook == NULL ) {
		dispatcher_reload_hook = PyObject_GetAttr(dispatcher, hook_name);
	};

	PyObject* result = PyObject_CallObject( dispatcher_reload_hook, NULL );

	Py_DECREF(hook_name);
	Py_DECREF(result);

}

static int Python_NewDispatcher(char* middleware_path, char* event_handler_path) {
  if( PyCallable_Check(dispatcher_class) ) {
    dispatcher_args = PyTuple_Pack( 2, PyUnicode_FromString(middleware_path), PyUnicode_FromString(event_handler_path) );
    dispatcher = PyObject_CallObject( dispatcher_class, dispatcher_args );

		Py_DECREF(dispatcher_args);

    if( dispatcher == NULL) {
      PyErr_Print();
      return -1;
    }
  } else {
    PyErr_Print();
    return -1;
  }

  dispatcher_hook_name = PyUnicode_FromString( hook_name );
  dispatcher_hook = PyObject_GetAttr(dispatcher, dispatcher_hook_name);

	dispatch_event_name = PyUnicode_FromString( dispatch_event_name_s );
	dispatch_event = PyObject_GetAttr(dispatcher, dispatch_event_name );

	Py_DECREF(dispatcher_hook_name);
	Py_DECREF(dispatch_event_name);

  if( dispatcher_hook == NULL ) {
    PyErr_Print();
    return -1;
  }

  return 0;
}

static void Python_SetEnv(char* python_path) {
  CoProcessLog( sdscatprintf(sdsempty(), "Setting PYTHONPATH to '%s'", python_path), "info");
  setenv("PYTHONPATH", python_path, 1 );
}

static struct CoProcessMessage* Python_DispatchHook(struct CoProcessMessage* object) {
	struct CoProcessMessage* outputObject = malloc(sizeof *outputObject);

	if( object->p_data == NULL ) {
		return outputObject;
	} else {

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
}

static void Python_DispatchEvent(char* event_json) {
	gilState = PyGILState_Ensure();
	printf("Python_DispatchEvent (C): %s\n", event_json);
	PyObject *args = PyTuple_Pack( 1, PyUnicode_FromString(event_json) );
	PyObject *result = PyObject_CallObject( dispatch_event, args );
	PyGILState_Release(gilState);
}

*/
import "C"

import (
	"errors"
	"os"
	"path"
	"strings"
	"unsafe"

	"github.com/Sirupsen/logrus"
)

// CoProcessName declares the driver name.
const CoProcessName string = "python"

// PythonDispatcher implements a CoProcessDispatcher
type PythonDispatcher struct {
	CoProcessDispatcher
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *PythonDispatcher) Dispatch(objectPtr *C.struct_CoProcessMessage) *C.struct_CoProcessMessage {

	var newObjectPtr *C.struct_CoProcessMessage
	newObjectPtr = C.Python_DispatchHook(objectPtr)

	return newObjectPtr
}

// DispatchEvent dispatches a Tyk event.
func (d *PythonDispatcher) DispatchEvent(eventJSON []byte) {
	var CEventJSON *C.char
	CEventJSON = C.CString(string(eventJSON))
	C.Python_DispatchEvent(CEventJSON)
	C.free(unsafe.Pointer(CEventJSON))
	return
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *PythonDispatcher) Reload() {
	C.Python_ReloadDispatcher()
}

// PythonInit initializes the Python interpreter.
func PythonInit() (err error) {
	result := C.Python_Init()
	if result == 0 {
		err = errors.New("Can't Py_Initialize()")
	}
	return err
}

// PythonLoadDispatcher creates reference to the dispatcher class.
func PythonLoadDispatcher() (err error) {
	result := C.Python_LoadDispatcher()
	if result == -1 {
		err = errors.New("Can't load dispatcher")
	}
	return err
}

// PythonNewDispatcher creates an instance of TykDispatcher.
func PythonNewDispatcher(middlewarePath string, eventHandlerPath string) (dispatcher CoProcessDispatcher, err error) {
	var CMiddlewarePath *C.char
	CMiddlewarePath = C.CString(middlewarePath)

	var CEventHandlerPath *C.char
	CEventHandlerPath = C.CString(eventHandlerPath)

	result := C.Python_NewDispatcher(CMiddlewarePath, CEventHandlerPath)

	if result == -1 {
		err = errors.New("Can't initialize a dispatcher")
	} else {
		dispatcher = &PythonDispatcher{}
	}

	C.free(unsafe.Pointer(CMiddlewarePath))
	C.free(unsafe.Pointer(CEventHandlerPath))

	return dispatcher, err
}

// PythonSetEnv sets PYTHONPATH, it's called before initializing the interpreter.
func PythonSetEnv(pythonPaths ...string) {
	var CPythonPath *C.char
	CPythonPath = C.CString(strings.Join(pythonPaths, ":"))
	C.Python_SetEnv(CPythonPath)

	C.free(unsafe.Pointer(CPythonPath))
}

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (dispatcher CoProcessDispatcher, err error) {

	workDir, _ := os.Getwd()

	dispatcherPath := path.Join(workDir, "coprocess/python")
	middlewarePath := path.Join(workDir, "middleware/python")
	eventHandlerPath := path.Join(workDir, "event_handlers")
	protoPath := path.Join(workDir, "coprocess/python/proto")

	PythonSetEnv(dispatcherPath, middlewarePath, protoPath, eventHandlerPath)

	PythonInit()
	PythonLoadDispatcher()

	dispatcher, err = PythonNewDispatcher(middlewarePath, eventHandlerPath)

	C.PyEval_ReleaseLock()

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
	}

	return dispatcher, err
}
