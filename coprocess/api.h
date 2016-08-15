#ifndef TYK_COPROCESS_API
#define TYK_COPROCESS_API

struct CoProcessMessage {
  void* p_data;
  int length;
};

extern void TykStoreData(char* key, char* value, int ttl);
extern char* TykGetData(char* key);
extern void TykTriggerEvent(char* event_name, char* payload);

extern void CoProcessLog(char *msg, char *level);

#endif
