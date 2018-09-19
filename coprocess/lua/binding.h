#include "../../coprocess/api.h"
#ifndef TYK_COPROCESS_LUA
#define TYK_COPROCESS_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

static void LuaInit();

static int LuaDispatchHook(struct CoProcessMessage*, struct CoProcessMessage*);
static void LuaDispatchEvent(char*);

void LoadCachedMiddleware(void*);
void LoadCachedModules(void*);

#endif
