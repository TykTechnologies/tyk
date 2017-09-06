package lib

import (
	"context"
)

// Module is the interface implemented by types that
// register themselves as modular plug-ins.
type Module interface {

	// Init initializes the module.
	//
	// The config argument can be asserted as an implementation of the
	// of the github.com/akutz/gpds/lib/v2.Config interface or older.
	Init(ctx context.Context, config interface{}) error
}

var mods = map[string]func() interface{}{}

// RegisterModule registers a new module with its name and function
// that returns a new, uninitialized object that can be asserted
// as the Module interface.
func RegisterModule(name string, ctor func() interface{}) {
	mods[name] = ctor
}

// NewModule instantiates a new instance of the module type with the
// specified name.
func NewModule(name string) Module {
	if obj, ok := mods[name]().(Module); ok {
		return obj
	}
	return nil
}
