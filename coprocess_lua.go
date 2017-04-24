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

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

static void LoadMiddleware(char* middleware_file, char* middleware_contents) {
}

static void LoadMiddlewareIntoState(lua_State* L, char* middleware_name, char* middleware_contents) {
	luaL_dostring(L, middleware_contents);
}

static struct CoProcessMessage* LuaDispatchHook(struct CoProcessMessage* object) {

	struct CoProcessMessage* outputObject = malloc(sizeof *outputObject);

	lua_State *L = luaL_newstate();

	luaL_openlibs(L);
	// luaL_dofile(L, "coprocess/lua/tyk/core.lua");
	LoadCachedModules(L);

	LoadCachedMiddleware(L);
	lua_getglobal(L, "dispatch");

	lua_pushlstring(L, object->p_data, object->length);
	int call_result = lua_pcall(L, 1, 2, 0);

	size_t lua_output_length = lua_tointeger(L, -1);
	const char* lua_output_data = lua_tolstring(L, 0, &lua_output_length);

	char* output = malloc(lua_output_length);
	memmove(output, lua_output_data, lua_output_length);

	lua_close(L);

	outputObject->p_data = (void*)output;
	outputObject->length = lua_output_length;

	return outputObject;
}

static void LuaDispatchEvent(char* event_json) {
	lua_State *L = luaL_newstate();
	luaL_openlibs(L);
	luaL_dofile(L, "coprocess/lua/tyk/core.lua");

	lua_getglobal(L, "dispatch_event");
	// lua_pushlstring(L, object->p_data, object->length);
	int call_result = lua_pcall(L, 1, 1, 0);

	lua_close(L);
}
*/
import "C"

import (
	"io/ioutil"
	"path/filepath"
	"unsafe"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
)

// CoProcessName specifies the driver name.
const CoProcessName = apidef.LuaDriver

const (
	// ModuleBasePath points to the Tyk modules path.
	ModuleBasePath = "coprocess/lua"
	// MiddlewareBasePath points to the custom middleware path.
	MiddlewareBasePath = "middleware/lua"
)

// MessageType sets the default message type.
var MessageType = coprocess.JsonMessage

// gMiddlewareCache will hold LuaDispatcher.gMiddlewareCache.
var gMiddlewareCache map[string]string
var gModuleCache map[string]string

// LuaDispatcher implements a coprocess.Dispatcher
type LuaDispatcher struct {
	// LuaDispatcher implements the coprocess.Dispatcher interface.
	coprocess.Dispatcher
	// MiddlewareCache will keep the middleware file name and contents in memory, the contents will be accessed when a Lua state is initialized.
	MiddlewareCache map[string]string
	ModuleCache     map[string]string
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *LuaDispatcher) Dispatch(objectPtr unsafe.Pointer) unsafe.Pointer {
	object := (*C.struct_CoProcessMessage)(objectPtr)
	newObjectPtr := C.LuaDispatchHook(object)
	return unsafe.Pointer(newObjectPtr)
}

// Reload will perform a middleware reload when a hot reload is triggered.
func (d *LuaDispatcher) Reload() {
	files, _ := ioutil.ReadDir(MiddlewareBasePath)

	if d.MiddlewareCache == nil {
		d.MiddlewareCache = make(map[string]string, len(files))
		gMiddlewareCache = d.MiddlewareCache
	} else {
		for k := range d.MiddlewareCache {
			delete(d.MiddlewareCache, k)
		}
	}

	for _, f := range files {
		middlewarePath := filepath.Join(MiddlewareBasePath, f.Name())
		contents, err := ioutil.ReadFile(middlewarePath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "coprocess",
			}).Error("Failed to read middleware file: ", err)
		}

		d.MiddlewareCache[f.Name()] = string(contents)
	}
}

func (d *LuaDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {
	for _, f := range b.FileList {
		fullPath := filepath.Join(basePath, f)
		contents, err := ioutil.ReadFile(fullPath)
		if err == nil {
			d.ModuleCache[f] = string(contents)
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "coprocess",
			}).Error("Failed to read bundle file: ", err)
		}
	}
}

func (d *LuaDispatcher) LoadModules() {
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Info("Loading Tyk/Lua modules.")

	if d.ModuleCache == nil {
		d.ModuleCache = make(map[string]string, 0)
		gModuleCache = d.ModuleCache
	}

	middlewarePath := filepath.Join(ModuleBasePath, "bundle.lua")
	contents, err := ioutil.ReadFile(middlewarePath)

	if err == nil {
		d.ModuleCache["bundle.lua"] = string(contents)
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Error("Failed to read bundle file: ", err)
	}
}

//export LoadCachedModules
func LoadCachedModules(luaState unsafe.Pointer) {
	for moduleName, moduleContents := range gModuleCache {
		cModuleName := C.CString(moduleName)
		cModuleContents := C.CString(moduleContents)
		C.LoadMiddlewareIntoState((*C.struct_lua_State)(luaState), cModuleName, cModuleContents)
		C.free(unsafe.Pointer(cModuleName))
		C.free(unsafe.Pointer(cModuleContents))
	}
}

//export LoadCachedMiddleware
func LoadCachedMiddleware(luaState unsafe.Pointer) {
	for middlewareName, middlewareContents := range gMiddlewareCache {
		cMiddlewareName := C.CString(middlewareName)
		cMiddlewareContents := C.CString(middlewareContents)
		C.LoadMiddlewareIntoState((*C.struct_lua_State)(luaState), cMiddlewareName, cMiddlewareContents)
		C.free(unsafe.Pointer(cMiddlewareName))
		C.free(unsafe.Pointer(cMiddlewareContents))
	}
}

func (d *LuaDispatcher) DispatchEvent(eventJSON []byte) {
	CEventJSON := C.CString(string(eventJSON))
	C.LuaDispatchEvent(CEventJSON)
	C.free(unsafe.Pointer(CEventJSON))
}

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (coprocess.Dispatcher, error) {
	dispatcher := &LuaDispatcher{}
	dispatcher.LoadModules()
	dispatcher.Reload()
	return dispatcher, nil
}
