from glob import glob
from os import getcwd, chdir, path

import tyk
from tyk.middleware import TykMiddleware
from tyk.object import TykCoProcessObject

from gateway import TykGateway as tyk

class TykDispatcher:
    '''A simple dispatcher'''

    def __init__(self, middleware_path):
        tyk.log( "Initializing dispatcher", "info" )
        self.middleware_path = path.join(middleware_path, '*.py')
        self.middlewares = []
        self.load_middlewares()

    def get_modules(self):
        files = glob(self.middleware_path)
        files = [ path.basename( f.replace('.py', '') ) for f in files ]
        return files

    def find_middleware(self, path):
        found_middleware = None
        if len(self.middlewares) > 0:
            for middleware in self.middlewares:
                if middleware.filepath == path and not found_middleware:
                    found_middleware = middleware
                    break
        return found_middleware

    def load_middlewares(self):
        tyk.log( "Loading middlewares.", "debug" )
        # chdir(self.middleware_path)
        for module_name in self.get_modules():
            middleware = self.find_middleware(module_name)
            if middleware:
                middleware.reload()
            else:
                middleware = TykMiddleware(module_name)
                self.middlewares.append(middleware)

    def purge_middlewares(self):
        tyk.log( "Purging middlewares.", "debug" )
        available_modules = self.get_modules()
        for middleware in self.middlewares:
            if not middleware.filepath in available_modules:
                tyk.log( "Purging middleware: '{0}'".format(middleware.filepath), "warning" )
                self.middlewares.remove(middleware)

    def reload(self):
        tyk.log( "Reloading middlewares.", "info" )
        self.purge_middlewares()
        self.load_middlewares()

    def find_hook(self, hook_type, hook_name):
        found_middleware, matching_hook_handler = None, None
        for middleware in self.middlewares:
            if hook_type in middleware.handlers:
                for handler in middleware.handlers[hook_type]:
                    if handler.name == hook_name:
                        found_middleware = middleware
                        matching_hook_handler = handler
        return found_middleware, matching_hook_handler

    def dispatch_hook(self, object_msg):
        try:
            object = TykCoProcessObject(object_msg)
            middleware, hook_handler = self.find_hook(object.hook_type, object.hook_name)
            if hook_handler:
                object = middleware.process(hook_handler, object)
            else:
                tyk.log( "Can't dispatch '{0}', hook is not defined.".format(object.hook_name), "error")
            return object.dump()
        except:
            tyk.log_error( "Can't dispatch, protocol error:" )
            return object_msg
