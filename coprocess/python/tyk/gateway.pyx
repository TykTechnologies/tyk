# Gateway API Cython binding
# Recompile with: cythonize gateway.pyx

cdef extern from "coprocess/api.h":
  void TykStoreData(char* key, char* value, int ttl);
  char* TykGetData(char* key);
  void TykTriggerEvent(char* event_name, char* payload);
  void CoProcess_Log(char *msg, char *level);

class TykGateway:
  def store_data(key, value, ttl):
    TykStoreData( key.encode('utf-8'), value.encode('utf-8'), ttl)
  def get_data(key):
    output = TykGetData(key.encode('utf-8'))
    return output.decode('utf-8')
  def trigger_event(event_name, payload):
    TykTriggerEvent( event_name.encode('utf-8'), payload.encode('utf-8'))
  def log(msg, level):
    CoProcess_Log( msg.encode('utf-8'), level.encode('utf-8') )
