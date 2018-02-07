from importlib import reload as reload_module
from importlib import invalidate_caches as invalidate_caches

from importlib.machinery import SourceFileLoader

import inspect
import tyk.decorators as decorators

from gateway import TykGateway as tyk

HandlerDecorators = list(map(lambda m: m[1], inspect.getmembers(decorators, inspect.isclass)))


class TykMiddleware:
    def __init__(self, module_path, module_name):
        tyk.log("Loading module: '{0}'".format(module_name), "info")
        self.module_path = module_path
        self.handlers = {}
        try:
            source = SourceFileLoader(module_name, self.module_path)
            self.module = source.load_module()
            self.register_handlers()
        except:
            tyk.log_error("Middleware initialization error:")

    def register_handlers(self):
        new_handlers = {}
        for attr in dir(self.module):
            attr_value = getattr(self.module, attr)
            if callable(attr_value):
                attr_type = type(attr_value)
                if attr_type in HandlerDecorators:
                    handler_type = attr_value.__class__.__name__.lower()
                    if handler_type not in new_handlers:
                        new_handlers[handler_type] = []
                    new_handlers[handler_type].append(attr_value)
        self.handlers = new_handlers

    def reload(self):
        try:
            invalidate_caches()
            reload_module(self.module)
            self.register_handlers()
        except:
            tyk.log_error("Reload error:")

    def process(self, handler, object):
        if handler.arg_count == 4:
            object.request, object.session, object.metadata = handler(
                object.request, object.session, object.metadata, object.spec)
        elif handler.arg_count == 3:
            object.request, object.session = handler(object.request, object.session, object.spec)
        return object
