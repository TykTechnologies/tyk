from importlib import import_module
import json

import tyk.decorators as decorators

class TykEvent:
    def __init__(self, event_json):
        self.__dict__ = json.loads(event_json)
        pass
