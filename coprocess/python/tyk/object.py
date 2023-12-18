from tyk.request import TykCoProcessRequest
from json import loads, dumps


class TykCoProcessObject:
    def __init__(self, object_msg):
        self.object = loads(object_msg)
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
        self.response = self.object.response

        if self.object.hook_type == 0:
            self.hook_type = ''
        elif self.object.hook_type == 1:
            self.hook_type = 'pre'
        elif self.object.hook_type == 2:
            self.hook_type = 'post'
        elif self.object.hook_type == 3:
            self.hook_type = 'postkeyauth'
        elif self.object.hook_type == 4:
            self.hook_type = 'customkeycheck'
        elif self.object.hook_type == 5:
            self.hook_type = 'response'

    def dump(self):
        new_object = dumps(self.object)
        return new_object, len(new_object)
