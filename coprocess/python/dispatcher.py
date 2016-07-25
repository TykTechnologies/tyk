from glob import glob
from os import getcwd, chdir, path
import json

import tyk
from tyk.middleware import TykMiddleware

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
