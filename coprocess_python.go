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

static int Python_Init() {
  CoProcess_Log( sdsnew("Initializing interpreter, Py_Initialize()"), "info");
  Py_Initialize();

	// This exposes the Cython interface as "gateway"
	PyInit_gateway();

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

static int Python_NewDispatcher(char* middleware_path) {
  if( PyCallable_Check(dispatcher_class) ) {
    dispatcher_args = PyTuple_Pack( 1, PyUnicode_FromString(middleware_path) );
    dispatcher = PyObject_CallObject( dispatcher_class, dispatcher_args );
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

  if( dispatcher_hook == NULL ) {
    PyErr_Print();
    return -1;
  }

  return 0;
}

static void Python_SetEnv(char* python_path) {
  CoProcess_Log( sdscatprintf(sdsempty(), "Setting PYTHONPATH to '%s'", python_path), "info");
  setenv("PYTHONPATH", python_path, 1 );
}

static char* Python_DispatchHook(char *object_json) {
  if( object_json == NULL ) {
    return NULL;
  } else {
    PyObject *args = PyTuple_Pack( 1, PyUnicode_FromString(object_json) );
    PyObject *result = PyObject_CallObject( dispatcher_hook, args );
    if( result == NULL ) {
      PyErr_Print();
      return NULL;
    } else {
      char *payload = PyUnicode_AsUTF8(result);
      return payload;
    }
  }
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"strings"
	"unsafe"

	"github.com/Sirupsen/logrus"
)

const CoProcessName string = "python"

type PythonDispatcher struct {
	CoProcessDispatcher
}

func (d *PythonDispatcher) DispatchHook(objectJson []byte) CoProcessObject {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Info("PythonDispatcher.DispatchHook")

	var CObjectStr *C.char
	CObjectStr = C.CString(string(objectJson))

	var CNewObjectStr *C.char
	CNewObjectStr = C.Python_DispatchHook(CObjectStr)

	var newObjectStr string
	newObjectStr = C.GoString(CNewObjectStr)

	var newObject CoProcessObject
	json.Unmarshal([]byte(newObjectStr), &newObject)

	return newObject

}

func PythonInit() (err error) {
	result := C.Python_Init()
	if result == 0 {
		err = errors.New("Can't Py_Initialize()")
	}
	return err
}

func PythonLoadDispatcher() (err error) {
	result := C.Python_LoadDispatcher()
	if result == -1 {
		err = errors.New("Can't load dispatcher")
	}
	return err
}

func PythonNewDispatcher(middlewarePath string) (err error, dispatcher CoProcessDispatcher) {
	var CMiddlewarePath *C.char
	CMiddlewarePath = C.CString(middlewarePath)

	result := C.Python_NewDispatcher(CMiddlewarePath)
	if result == -1 {
		err = errors.New("Can't initialize a dispatcher")
	} else {
		dispatcher = &PythonDispatcher{}
	}

	C.free(unsafe.Pointer(CMiddlewarePath))

	return err, dispatcher
}

func PythonSetEnv(pythonPaths ...string) {
	var CPythonPath *C.char
	CPythonPath = C.CString(strings.Join(pythonPaths, ":"))
	C.Python_SetEnv(CPythonPath)

	C.free(unsafe.Pointer(CPythonPath))
}

func CoProcessInit() (err error) {

	workDir, _ := os.Getwd()

	dispatcherPath := path.Join(workDir, "coprocess/python")
	middlewarePath := path.Join(workDir, "middleware/python")

	PythonSetEnv(dispatcherPath, middlewarePath)

	PythonInit()
	PythonLoadDispatcher()
	err, GlobalDispatcher = PythonNewDispatcher(middlewarePath)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
	}

	return err
}
