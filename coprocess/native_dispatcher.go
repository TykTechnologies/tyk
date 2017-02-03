// +build coprocess
// +build !grpc

package coprocess

/*
#include <stdio.h>

#include "sds/sds.h"

#include "api.h"

*/
import "C"
import "unsafe"

import (
	"github.com/TykTechnologies/tyk/apidef"
)

const (
	_ = iota
	JsonMessage
	ProtobufMessage
)

// Dispatcher defines a basic interface for the CP dispatcher, check PythonDispatcher for reference.
type Dispatcher interface {
	// Dispatch takes and returns a pointer to a CoProcessMessage struct, see coprocess/api.h for details. This is used by CP bindings.
	Dispatch(unsafe.Pointer) unsafe.Pointer

	// DispatchEvent takes an event JSON, as bytes. Doesn't return.
	DispatchEvent([]byte)

	// DispatchObject takes and returns a coprocess.Object pointer, this is used by gRPC.
	DispatchObject(*Object) (*Object, error)

	// LoadModules is called the first time a CP binding starts. Used by Lua.
	LoadModules()

	// HandleMiddlewareCache is called when a bundle has been loaded and the dispatcher needs to cache its contents. Used by Lua.
	HandleMiddlewareCache(*apidef.BundleManifest, string)

	// Reload is called when a hot reload is triggered. Used by all the CPs.
	Reload()
}
