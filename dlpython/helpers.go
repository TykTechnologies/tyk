package python

/*
#include <stdlib.h>
typedef struct _pygilstate {} PyGILState_STATE;

PyGILState_STATE gilState;
*/
import "C"
import (
	"errors"
	"strings"
	"unsafe"
)

const (
	pythonPathKey = "PYTHONPATH"
)

// SetPythonPath is a helper for setting PYTHONPATH.
func SetPythonPath(p []string) {
	mergedPaths := strings.Join(p, ":")
	path := C.CString(mergedPaths)
	defer C.free(unsafe.Pointer(path))
	key := C.CString(pythonPathKey)
	defer C.free(unsafe.Pointer(key))
	C.setenv(key, path, 1)
}

// LoadModuleDict wraps PyModule_GetDict.
func LoadModuleDict(m string) (unsafe.Pointer, error) {
	mod := C.CString(m)
	defer C.free(unsafe.Pointer(mod))
	modName := PyUnicode_FromString(mod)
	if modName == nil {
		return nil, errors.New("PyUnicode_FromString failed")
	}
	modObject := PyImport_Import(modName)
	if modObject == nil {
		return nil, errors.New("PyImport_Import failed")
	}
	dict := PyModule_GetDict(modObject)
	if dict == nil {
		return nil, errors.New("PyModule_GetDict failed")
	}
	return unsafe.Pointer(dict), nil
}

// GetItem wraps PyDict_GetItemString
func GetItem(d unsafe.Pointer, k string) (unsafe.Pointer, error) {
	key := C.CString(k)
	defer C.free(unsafe.Pointer(key))
	obj := ToPyObject(d)
	item := PyDict_GetItemString(obj, key)
	if item == nil {
		return nil, errors.New("GetItem failed")
	}
	return unsafe.Pointer(item), nil
}

// PyRunSimpleString wraps PyRun_SimpleStringFlags
func PyRunSimpleString(s string) {
	cstr := C.CString(s)
	defer C.free(unsafe.Pointer(cstr))
	PyRun_SimpleStringFlags(cstr, nil)
}

// PyTupleNew wraps PyTuple_New
func PyTupleNew(size int) (unsafe.Pointer, error) {
	tup := PyTuple_New(C.long(size))
	if tup == nil {
		return nil, errors.New("PyTupleNew failed")
	}
	return unsafe.Pointer(tup), nil
}

// PyTupleSetItem wraps PyTuple_SetItem
func PyTupleSetItem(tup unsafe.Pointer, pos int, o interface{}) error {
	switch o.(type) {
	case string:
		str := C.CString(o.(string))
		defer C.free(unsafe.Pointer(str))
		pystr := PyUnicode_FromString(str)
		if pystr == nil {
			return errors.New("PyUnicode_FromString failed")
		}
		ret := PyTuple_SetItem(ToPyObject(tup), C.long(pos), pystr)
		if ret != 0 {
			return errors.New("PyTuple_SetItem failed")
		}
	default:
		// Assume this is a PyObject
		obj := o.(unsafe.Pointer)
		ret := PyTuple_SetItem(ToPyObject(tup), C.long(pos), ToPyObject(obj))
		if ret != 0 {
			return errors.New("PyTuple_SetItem failed")
		}
	}
	return nil
}

// PyTupleGetItem wraps PyTuple_GetItem
func PyTupleGetItem(tup unsafe.Pointer, pos int) (unsafe.Pointer, error) {
	item := PyTuple_GetItem(ToPyObject(tup), C.long(pos))
	if item == nil {
		return nil, errors.New("PyTupleGetItem failed")
	}
	return unsafe.Pointer(item), nil
}

// PyObjectCallObject wraps PyObject_CallObject
func PyObjectCallObject(o unsafe.Pointer, args unsafe.Pointer) (unsafe.Pointer, error) {
	ret := PyObject_CallObject(ToPyObject(o), ToPyObject(args))
	if ret == nil {
		return nil, errors.New("PyObjectCallObject failed")
	}
	return unsafe.Pointer(ret), nil
}

// PyObjectGetAttr wraps PyObject_GetAttr
func PyObjectGetAttr(o unsafe.Pointer, attr interface{}) (unsafe.Pointer, error) {
	switch attr.(type) {
	case string:
		str := C.CString(attr.(string))
		defer C.free(unsafe.Pointer(str))
		pystr := PyUnicode_FromString(str)
		if pystr == nil {
			return nil, errors.New("PyUnicode_FromString failed")
		}
		ret := PyObject_GetAttr(ToPyObject(o), pystr)
		if ret == nil {
			return nil, errors.New("PyObjectGetAttr failed")
		}
		return unsafe.Pointer(ret), nil
	}
	return nil, nil
}

// PyBytesFromString wraps PyBytesFromString
func PyBytesFromString(input []byte) (unsafe.Pointer, error) {
	data := C.CBytes(input)
	defer C.free(unsafe.Pointer(data))
	ret := PyBytes_FromStringAndSize((*C.char)(data), C.long(len(input)))
	if ret == nil {
		return nil, errors.New("PyBytesFromString failed")
	}
	return unsafe.Pointer(ret), nil
}

// PyBytesAsString wraps PyBytes_AsString
func PyBytesAsString(o unsafe.Pointer, l int) ([]byte, error) {
	obj := ToPyObject(o)
	cstr := PyBytes_AsString(obj)
	if cstr == nil {
		return nil, errors.New("PyBytes_AsString as string failed")
	}
	str := C.GoBytes(unsafe.Pointer(cstr), C.int(l))
	b := []byte(str)
	return b, nil
}

// PyLongAsLong wraps PyLong_AsLong
func PyLongAsLong(o unsafe.Pointer) int {
	l := PyLong_AsLong(ToPyObject(o))
	return int(l)
}

func PyIncRef(o unsafe.Pointer) {
	Py_IncRef(ToPyObject(o))
}

func PyDecRef(o unsafe.Pointer) {
	Py_DecRef(ToPyObject(o))
}
