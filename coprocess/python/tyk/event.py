from importlib import import_module
import json

import tyk.decorators as decorators


class TykEventHandler:
    def __init__(self, name, callback):
        self.name = name
        self.callback = callback

    def process(self, event):
        print("process", event)
        self.callback(event.message, event.spec)

    def from_module(module_name):
        module = import_module(module_name)
        event_handlers = []
        for attr in dir(module):
            attr_value = getattr(module, attr)
            if callable(attr_value):
                attr_type = type(attr_value)
                if attr_type == decorators.Event:
                    event_handler = TykEventHandler(attr, attr_value)
                    event_handlers.append(event_handler)
        return event_handlers


class TykEvent:
    def __init__(self, event_json):
        self.__dict__ = json.loads(event_json)
        pass
