#ifndef TYK_COPROCESS_API
#define TYK_COPROCESS_API

extern void TykStoreData(char* key, char* value, int ttl);
extern char* TykGetData(char* key);
extern void TykTriggerEvent(char* event_name, char* payload);

extern void CoProcess_Log(char *msg, char *level);
#endif
