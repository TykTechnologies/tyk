#include "../../coprocess/api.h"
#ifndef TYK_COPROCESS_LUA
#define TYK_COPROCESS_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

static void LuaInit();
// static void Node_SetEnv(char*);

static struct CoProcessMessage* LuaDispatchHook(struct CoProcessMessage*);
// static void Python_DispatchEvent(char*);

lua_State *L;

#endif
