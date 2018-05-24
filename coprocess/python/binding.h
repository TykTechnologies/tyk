#include "../../coprocess/api.h"
#ifndef TYK_COPROCESS_PYTHON
#define TYK_COPROCESS_PYTHON

static int Python_Init();
static void Python_SetEnv(char*);

static int Python_LoadDispatcher();
static int Python_NewDispatcher(char*);
static void Python_ReloadDispatcher();

static struct CoProcessMessage* Python_DispatchHook(struct CoProcessMessage*);
static void Python_DispatchEvent(char*);

#endif
