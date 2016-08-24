// +build coprocess
// +build lua

package main

/*
#cgo pkg-config: luajit

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

#include "coprocess/lua/binding.h"

static void LuaInit() {
}

static struct CoProcessMessage* LuaDispatchHook(struct CoProcessMessage* object) {
	struct CoProcessMessage* outputObject = malloc(sizeof *outputObject);

  return outputObject;
}
*/
import "C"

import(
  "unsafe"

  "github.com/TykTechnologies/tyk/coprocess"
  "github.com/Sirupsen/logrus"
)

// CoProcessName declares the driver name.
const CoProcessName string = "lua"

// LuaDispatcher implements a coprocess.Dispatcher
type LuaDispatcher struct {
	coprocess.Dispatcher
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *LuaDispatcher) Dispatch(objectPtr unsafe.Pointer) unsafe.Pointer {

	var object *C.struct_CoProcessMessage
	object = (*C.struct_CoProcessMessage)(objectPtr)

	var newObjectPtr *C.struct_CoProcessMessage
	newObjectPtr = C.LuaDispatchHook(object)

	return unsafe.Pointer(newObjectPtr)
}

func LuaInit() {
  C.LuaInit()
}

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (dispatcher coprocess.Dispatcher, err error) {

  LuaInit()

  dispatcher, err = &LuaDispatcher{}, nil

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error(err)
	}

	return dispatcher, err
}
