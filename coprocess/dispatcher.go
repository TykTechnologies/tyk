package coprocess

/*
#include <stdio.h>

#include "sds/sds.h"

#include "api.h"

*/
import "C"
import "unsafe"

const(
	_ = iota
	JsonMessage
	ProtobufMessage
)

// CoProcessDispatcher defines a basic interface for the CP dispatcher, check PythonDispatcher for reference.
type Dispatcher interface {
	Dispatch(unsafe.Pointer) unsafe.Pointer
	DispatchEvent([]byte)
	LoadModules()
	Reload()
}
