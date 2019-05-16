// +build coprocess
// +build python

package gateway

/*
#cgo pkg-config: python3
#cgo python CFLAGS: -DENABLE_PYTHON -DPy_LIMITED_API


#include <Python.h>

#include <stdio.h>
#include <stdlib.h>

#include "../coprocess/sds/sds.h"

#include "../coprocess/api.h"

#include "../coprocess/python/binding.h"
#include "../coprocess/python/dispatcher.h"

#include "../coprocess/python/tyk/gateway_wrapper.h"

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
	PyObject* module_name = PyUnicode_FromString( dispatcher_module_name );
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
	PyObject* hook_name = PyUnicode_FromString(dispatcher_reload);
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

static int Python_NewDispatcher(char* bundle_root_path) {
	PyThreadState*  mainThreadState = PyEval_SaveThread();
	gilState = PyGILState_Ensure();
	if( PyCallable_Check(dispatcher_class) ) {
		dispatcher_args = PyTuple_Pack( 1, PyUnicode_FromString(bundle_root_path) );
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

static int Python_DispatchHook(struct CoProcessMessage* object, struct CoProcessMessage* new_object) {
	if (object->p_data == NULL) {
		free(object);
		return -1;
	}

	gilState = PyGILState_Ensure();
	PyObject* input = PyBytes_FromStringAndSize(object->p_data, object->length);
	PyObject* args = PyTuple_Pack( 1, input );

	PyObject* result = PyObject_CallObject( dispatcher_hook, args );

	free(object->p_data);
	free(object);

	Py_DECREF(input);
	Py_DECREF(args);

	if( result == NULL ) {
		PyErr_Print();
		PyGILState_Release(gilState);
		return -1;
	}
	PyObject* new_object_msg_item = PyTuple_GetItem( result, 0 );
	char* output = PyBytes_AsString(new_object_msg_item);

	PyObject* new_object_msg_length = PyTuple_GetItem( result, 1 );
	int msg_length = PyLong_AsLong(new_object_msg_length);

	// Copy the message in order to avoid accessing the result PyObject internal buffer:
	char* output_copy = malloc(msg_length);
	memcpy(output_copy, output, msg_length);

	Py_DECREF(result);

	new_object->p_data= (void*)output_copy;
	new_object->length = msg_length;

	PyGILState_Release(gilState);
	return 0;
}

static void Python_DispatchEvent(char* event_json) {
	gilState = PyGILState_Ensure();
	PyObject* args = PyTuple_Pack( 1, PyUnicode_FromString(event_json) );
	PyObject* result = PyObject_CallObject( dispatch_event, args );
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
	"sync"
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
	mu sync.Mutex
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *PythonDispatcher) Dispatch(objectPtr unsafe.Pointer, newObjectPtr unsafe.Pointer) error {
	object := (*C.struct_CoProcessMessage)(objectPtr)
	newObject := (*C.struct_CoProcessMessage)(newObjectPtr)

	if result := C.Python_DispatchHook(object, newObject); result != 0 {
		return errors.New("Dispatch error")
	}
	return nil
}

// DispatchEvent dispatches a Tyk event.
func (d *PythonDispatcher) DispatchEvent(eventJSON []byte) {
	CEventJSON := C.CString(string(eventJSON))
	defer C.free(unsafe.Pointer(CEventJSON))
	C.Python_DispatchEvent(CEventJSON)
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *PythonDispatcher) Reload() {
	C.Python_ReloadDispatcher()
}

// HandleMiddlewareCache isn't used by Python.
func (d *PythonDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {
	d.mu.Lock()
	go func() {
		runtime.LockOSThread()
		CBundlePath := C.CString(basePath)
		defer func() {
			runtime.UnlockOSThread()
			C.free(unsafe.Pointer(CBundlePath))
			d.mu.Unlock()
		}()
		C.Python_HandleMiddlewareCache(CBundlePath)
	}()
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
func PythonNewDispatcher(bundleRootPath string) (coprocess.Dispatcher, error) {
	CBundleRootPath := C.CString(bundleRootPath)
	defer C.free(unsafe.Pointer(CBundleRootPath))

	result := C.Python_NewDispatcher(CBundleRootPath)
	if result == -1 {
		return nil, errors.New("can't initialize a dispatcher")
	}

	dispatcher := &PythonDispatcher{mu: sync.Mutex{}}

	return dispatcher, nil
}

// PythonSetEnv sets PYTHONPATH, it's called before initializing the interpreter.
func PythonSetEnv(pythonPaths ...string) {
	if config.Global().CoProcessOptions.PythonPathPrefix == "" {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Warning("Python path prefix isn't set (check \"python_path_prefix\" in tyk.conf)")
	}
	CPythonPath := C.CString(strings.Join(pythonPaths, ":"))
	defer C.free(unsafe.Pointer(CPythonPath))
	C.Python_SetEnv(CPythonPath)
}

// getBundlePaths will return an array of the available bundle directories:
func getBundlePaths() []string {
	bundlePath := filepath.Join(config.Global().MiddlewarePath, "bundles")
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
	workDir := config.Global().CoProcessOptions.PythonPathPrefix

	dispatcherPath := filepath.Join(workDir, "coprocess", "python")
	protoPath := filepath.Join(workDir, "coprocess", "python", "proto")
	bundleRootPath := filepath.Join(config.Global().MiddlewarePath, "bundles")

	paths := []string{dispatcherPath, protoPath, bundleRootPath}

	// initDone is used to signal the end of Python initialization step:
	initDone := make(chan error)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		PythonSetEnv(paths...)
		PythonInit()
		PythonLoadDispatcher()
		dispatcher, err = PythonNewDispatcher(bundleRootPath)
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
