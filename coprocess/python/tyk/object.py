import msgpack

from tyk.session import TykSession
from tyk.request import TykCoProcessRequest

class TykCoProcessObject:
    def __init__(self, object_msg):
        self.object = msgpack.unpackb(object_msg, use_list=False, encoding='utf-8')

        self.request = TykCoProcessRequest(self.object['request'])
        self.session = TykSession(self.object['session'])

        # Should we require these keys?
        if 'metadata' in self.object:
            self.metadata = self.object['metadata']
        else:
            self.metadata = {}

        if 'spec' in self.object:
            self.spec = self.object['spec']
        else:
            self.spec = {}

        if 'hook_type' in self.object:
            self.hook_type = self.object['hook_type']
        else:
            self.spec = {}

    def dump(self):
        self.object['request'] = self.request.__dict__
        self.object['session'] = self.session.__dict__
        self.object['metadata'] = self.metadata

        new_object = msgpack.packb(self.object, use_bin_type=True)
        return new_object, len(new_object)
