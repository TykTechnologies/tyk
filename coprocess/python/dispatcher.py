from importlib import import_module
from glob import glob
from os import getcwd, chdir, path

import json, inspect, tyk, tyk.decorators

HandlerDecorators = list( map( lambda m: m[1], inspect.getmembers(tyk.decorators, inspect.isclass) ) )

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

    def process(self, handler, payload, payload_type):
        print("TykMiddleware.process()", payload)
        request, session = handler(payload, {})
        return request

class TykDispatcher:
    '''A simple dispatcher'''

    def __init__(self, middleware_path):
        print("TykDispatcher.__init__")
        self.middleware_path = middleware_path
        self.middlewares = []
        self.load_middlewares()

    def load_middlewares(self):
        print("TykDispatcher.load_middlewares()")
        middleware_path = path.join(self.middleware_path, '*.py')
        # chdir(self.middleware_path)
        for filename in glob(middleware_path):
            filename = filename.replace('.py', '')
            basename = path.basename(filename)
            middleware = TykMiddleware(basename)
            self.middlewares.append(middleware)

    def dispatch_hook(self, payload, payload_type):
        print("TykDispatcher.dispatch_hook: ", payload, payload_type)

        payload = json.loads(payload)

        for middleware in self.middlewares:
            if payload_type in middleware.handlers:
                for handler in middleware.handlers[payload_type]:
                    payload = middleware.process(handler, payload, payload_type)
                    print("payload is = ", payload)

        payload = json.dumps(payload)
        return payload
