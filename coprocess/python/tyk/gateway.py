import ctypes
parent = ctypes.cdll.LoadLibrary(None)

parent.TykGetData.argtypes = [ctypes.c_char_p]
parent.TykGetData.restype = ctypes.c_char_p

parent.TykStoreData.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]

class TykGateway():
    def log(message, level):
        message_p = ctypes.c_char_p(bytes(message, "utf-8"))
        level_p = ctypes.c_char_p(bytes(level, "utf-8"))
        parent.CoProcessLog(message_p, level_p)

    def log_error(message):
        message_p = ctypes.c_char_p(bytes(message, "utf-8"))
        level_p = ctypes.c_char_p(bytes("error", "utf-8"))
        parent.CoProcessLog(message_p, level_p)

    def get_data(key):
        key_p = ctypes.c_char_p(bytes(key, "utf-8"))
        return parent.TykGetData(key_p)

    def store_data(key, value, ttl):
        key_p = ctypes.c_char_p(bytes(key, "utf-8"))
        value_p = ctypes.c_char_p(bytes(value, "utf-8"))
        ttl_int = ctypes.c_int(ttl)
        parent.TykStoreData(key_p, value_p, ttl_int)

    def trigger_event(name, payload):
        name_p = ctypes.c_char_p(bytes(name, "utf-8"))
        payload_p = ctypes.c_char_p(bytes(payload, "utf-8"))
        parent.TykTriggerEvent(name_p, payload_p)