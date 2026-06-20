package python

/*
typedef struct _pyobject {} PyObject;
*/
import "C"
import "unsafe"

// SW-REQ-123
func PyUnicodeFromString(s string) unsafe.Pointer {
	cstr := C.CString(s)
	ret := PyUnicode_FromString(cstr)
	return unsafe.Pointer(ret)
}

// SW-REQ-123
func PyImportImport(modulePtr unsafe.Pointer) unsafe.Pointer {
	ptr := (*C.PyObject)(modulePtr)
	ret := PyImport_Import(ptr)
	return unsafe.Pointer(ret)
}
