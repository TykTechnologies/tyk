#include "../../coprocess/api.h"
#ifndef TYK_COPROCESS_LUA
#define TYK_COPROCESS_LUA

static void LuaInit();
// static void Node_SetEnv(char*);

static struct CoProcessMessage* LuaDispatchHook(struct CoProcessMessage*);
// static void Python_DispatchEvent(char*);

#endif
