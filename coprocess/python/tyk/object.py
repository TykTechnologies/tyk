from tyk.session import TykSession
from tyk.request import TykCoProcessRequest

import coprocess_common_pb2 as HookType

from coprocess_object_pb2 import Object
from coprocess_mini_request_object_pb2 import MiniRequestObject
from coprocess_return_overrides_pb2 import ReturnOverrides
from coprocess_session_state_pb2 import SessionState


class TykCoProcessObject:
    def __init__(self, object_msg):
        self.object = Object()
        try:
            self.object.ParseFromString(object_msg)
        except:
            # TODO: add error handling
            pass

        self.request = TykCoProcessRequest(self.object.request)
        # self.session = TykSession(self.object.session)
        self.session = self.object.session
        self.spec = self.object.spec
        self.metadata = self.object.metadata
        self.hook_name = self.object.hook_name

        if self.object.hook_type == HookType.Unknown:
            self.hook_type = ''
        elif self.object.hook_type == HookType.Pre:
            self.hook_type = 'pre'
        elif self.object.hook_type == HookType.Post:
            self.hook_type = 'post'
        elif self.object.hook_type == HookType.PostKeyAuth:
            self.hook_type = 'postkeyauth'
        elif self.object.hook_type == HookType.CustomKeyCheck:
            self.hook_type = 'customkeycheck'

    def dump(self):
        new_object = self.object.SerializeToString()
        return new_object, len(new_object)
