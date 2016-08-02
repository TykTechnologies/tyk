from glob import glob
from os import getcwd, chdir, path
import json

import tyk
from tyk.middleware import TykMiddleware
from tyk.object import TykCoProcessObject

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

    def dispatch_hook(self, object_json):
        object = TykCoProcessObject(object_json)

        for middleware in self.middlewares:
            if object.hook_type in middleware.handlers:
                for handler in middleware.handlers[object.hook_type]:
                    object = middleware.process(handler, object)

        return object.dump()
