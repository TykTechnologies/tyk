from cffi import FFI
ffi = FFI()
ffi.cdef("""
void TykStoreData(char* key, char* value, int ttl);
void TykTriggerEvent(char* event_name, char* payload);
void CoProcess_Log(char *msg, char *level);
""")
lib = ffi.dlopen(None)

# TODO: Try to load the API header file (avoid code repetition, like in ffi.cdef)

class TykGateway:
    def store_data(key, value, ttl):
        lib.TykStoreData( key.encode('utf-8'), value.encode('utf-8'), ttl)
    def trigger_event(event_name, payload):
        lib.TykTriggerEvent( event_name.encode('utf-8'), payload.encode('utf-8'))
    def log(msg, level):
        pass
