package coprocess

import (
	"context"

	"github.com/TykTechnologies/tyk/apidef"
)

// Dispatcher defines a basic interface for the CP dispatcher, check PythonDispatcher for reference.
type Dispatcher interface {
	// Dispatch takes and returns a pointer to a CoProcessMessage struct, see coprocess/api.h for details.
	// This is used by CP bindings. For backward compatibility with existing dispatchers.
	Dispatch(*Object) (*Object, error)

	// DispatchEvent takes an event JSON, as bytes. Doesn't return.
	DispatchEvent([]byte)

	// DispatchObject takes and returns a coprocess.Object pointer, this is used by gRPC.
	// Deprecated: Use Dispatch or DispatchWithContext instead.
	DispatchObject(*Object) (*Object, error)

	// LoadModules is called the first time a CP binding starts. Used by Lua.
	LoadModules()

	// HandleMiddlewareCache is called when a bundle has been loaded and the dispatcher needs to cache its contents. Used by Lua.
	HandleMiddlewareCache(*apidef.BundleManifest, string)

	// Reload is called when a hot reload is triggered. Used by all the CPs.
	Reload()
}

// DispatcherWithContext extends Dispatcher with context-aware dispatch capabilities.
// This interface should be used for new implementations that support trace propagation
// and other context-based features.
type DispatcherWithContext interface {
	Dispatcher

	// DispatchWithContext takes a context and a pointer to a CoProcessMessage struct, returns a pointer to a CoProcessMessage struct.
	// The context is used to propagate trace context and other request-scoped values.
	// This is the preferred method for new implementations.
	DispatchWithContext(context.Context, *Object) (*Object, error)
}
