#ifndef TYK_COPROCESS_PYTHON
#define TYK_COPROCESS_PYTHON
static int Python_Init();
static int Python_LoadDispatcher();
static int Python_NewDispatcher(char*);
static void Python_SetEnv(char*);
static char* Python_DispatchHook(char*, char*);
#endif
