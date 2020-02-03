from session import TykSession

import ctypes

parent = ctypes.cdll.LoadLibrary(None)

parent.TykGetData.argtypes = [ctypes.c_char_p]
parent.TykGetData.restype = ctypes.c_char_p

parent.TykStoreData.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]

class tyk_get_session_ret(ctypes.Structure):
    _fields_ = [
        # ('session_buf', ctypes.c_char_p),
        ('session_buf', ctypes.c_void_p),
        ('buflen', ctypes.c_int)
    ]

parent.TykGetSession.restype = ctypes.POINTER(tyk_get_session_ret)

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
        # value_p = ctypes.c_char_p(bytes(value, "utf-8"))
        value_p = ctypes.c_char_p(value)
        ttl_int = ctypes.c_int(ttl)
        parent.TykStoreData(key_p, value_p, ttl_int)

    def set_session(token, session, schedule_update):
        raw_session = session.SerializeToString()
        token_p = ctypes.c_char_p(bytes(token, "utf-8"))
        raw_session_p = ctypes.c_char_p(raw_session)
        parent.TykSetSession(token_p, raw_session_p, len(raw_session))

    def get_session(spec, token):
        token_p = ctypes.c_char_p(bytes(token, "utf-8"))
        org_p = ctypes.c_char_p(bytes(spec['OrgID'], "utf-8"))
        ret_ptr = parent.TykGetSession(org_p, token_p)
        # Handle null pointer:
        if not ret_ptr:
            return None
        ret = ret_ptr.contents
        # Initialize a new PB session object:
        session = TykSession()
        raw_session = ctypes.string_at(ret.session_buf, ret.buflen)
        session.ParseFromString(raw_session)
        # Free memory that was allocated on the Go side:
        parent.free(ret.session_buf)
        parent.free(ret_ptr)
        return session

    def trigger_event(name, payload):
        name_p = ctypes.c_char_p(bytes(name, "utf-8"))
        payload_p = ctypes.c_char_p(bytes(payload, "utf-8"))
        parent.TykTriggerEvent(name_p, payload_p)