from importlib import import_module
import inspect
import tyk.decorators as decorators

HandlerDecorators = list( map( lambda m: m[1], inspect.getmembers(decorators, inspect.isclass) ) )

class TykMiddleware:
    def __init__(self, filepath):
        print("Loading:", filepath )
        self.module = import_module(filepath)
        self.handlers = {}
        for attr in dir(self.module):
            attr_value = getattr(self.module, attr)
            if callable(attr_value):
                attr_type = type(attr_value)
                if attr_type in HandlerDecorators:
                    handler_type = attr_value.__class__.__name__.lower()
                    if handler_type not in self.handlers:
                        self.handlers[handler_type] = []
                    self.handlers[handler_type].append(attr_value)

    def process(self, handler, object):
        object.request, object.session = handler(object.request, object.session, object.spec)
        return object
