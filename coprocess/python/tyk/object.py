import json

class TykCoProcessObject:
    def __init__(self, object_json):
        self.object = json.loads(object_json)
        self.request = self.object['request']
        self.session = self.object['session']
        self.spec = self.object['spec']
        self.hook_type = self.object['hook_type']

    def dump(self):
        self.object['request'] = self.request
        self.object['session'] = self.session
        return json.dumps(self.object)
