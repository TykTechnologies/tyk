from glob import glob
from os import path
import sys, traceback

from tyk.middleware import TykMiddleware
from tyk.object import TykCoProcessObject
from tyk.event import TykEvent, TykEventHandler

from gateway import TykGateway as tyk


class TykDispatcher:
    '''A simple dispatcher'''

    def __init__(self, middleware_path, event_handler_path, bundle_paths):
        tyk.log("Initializing dispatcher", "info")
        self.event_handler_path = path.join(event_handler_path, '*.py')
        self.event_handlers = {}
        self.load_event_handlers()

        self.middleware_path = path.join(middleware_path, '*.py')

        self.bundle_paths = bundle_paths.split(":")

        self.middlewares = []
        self.hook_table = {}

    def get_modules(self, the_path):
        files = glob(the_path)
        files = [path.basename(f.replace('.py', '')) for f in files]
        return files

    def find_middleware(self, path):
        found_middleware = None
        if len(self.middlewares) > 0:
            for middleware in self.middlewares:
                if middleware.module_path == path and not found_middleware:
                    found_middleware = middleware
                    break
        return found_middleware

    def load_bundle(self, base_bundle_path):
        bundle_path = path.join(str(base_bundle_path), '*.py')
        bundle_modules = self.get_modules(bundle_path)
        sys.path.append(base_bundle_path)
        for module_name in bundle_modules:
            module_filename = "{0}.py".format(module_name)
            module_path = path.join(base_bundle_path, module_filename)
            middleware = self.find_middleware(module_name)
            if middleware:
                middleware.reload()
            else:
                middleware = TykMiddleware(module_path, module_name)
                self.middlewares.append(middleware)

        self.update_hook_table()
    def load_middlewares(self):
        tyk.log("Loading middlewares.", "debug")
        available_modules = self.get_modules(self.middleware_path)
        for module_name in available_modules:
            middleware = self.find_middleware(module_name)
            if middleware:
                middleware.reload()
            else:
                middleware = TykMiddleware(module_name)
                self.middlewares.append(middleware)
        self.update_hook_table()

    def purge_middlewares(self):
        tyk.log("Purging middlewares.", "debug")
        available_modules = self.get_modules(self.middleware_path)
        for middleware in self.middlewares:
            if middleware.filepath not in available_modules:
                tyk.log("Purging middleware: '{0}'".format(middleware.filepath), "warning")
                self.middlewares.remove(middleware)

    def update_hook_table(self):
        new_hook_table = {}
        for middleware in self.middlewares:
            for hook_type in middleware.handlers:
                for handler in middleware.handlers[hook_type]:
                    handler.middleware = middleware
                    new_hook_table[handler.name] = handler
        self.hook_table = new_hook_table

    def find_hook_by_type_and_name(self, hook_type, hook_name):
        found_middleware, matching_hook_handler = None, None
        for middleware in self.middlewares:
            if hook_type in middleware.handlers:
                for handler in middleware.handlers[hook_type]:
                    if handler.name == hook_name:
                        found_middleware = middleware
                        matching_hook_handler = handler
        return found_middleware, matching_hook_handler

    def find_hook_by_name(self, hook_name):
        hook_handler, middleware = None, None
        if hook_name in self.hook_table:
            hook_handler = self.hook_table[hook_name]
            middleware = hook_handler.middleware
        return middleware, hook_handler

    def dispatch_hook(self, object_msg):
        try:
            object = TykCoProcessObject(object_msg)
            middleware, hook_handler = self.find_hook_by_name(object.hook_name)
            if hook_handler:
                object = middleware.process(hook_handler, object)
            else:
                tyk.log("Can't dispatch '{0}', hook is not defined.".format(object.hook_name), "error")
            return object.dump()
        except:
            exc_trace = traceback.format_exc()
            print(exc_trace)
            tyk.log_error("Can't dispatch, error:")

            return object_msg

    def purge_event_handlers(self):
        tyk.log("Purging event handlers.", "debug")
        self.event_handlers = {}

    def load_event_handlers(self):
        tyk.log("Loading event handlers.", "debug")
        for module_name in self.get_modules(self.event_handler_path):
            event_handlers = TykEventHandler.from_module(module_name)
            for event_handler in event_handlers:
                self.event_handlers[event_handler.name] = event_handler

    def find_event_handler(self, handler_name):
        handler = None
        if handler_name in self.event_handlers:
            handler = self.event_handlers[handler_name]
        return handler

    def dispatch_event(self, event_json):
        try:
            event = TykEvent(event_json)
            event_handler = self.find_event_handler(event.handler_name)
            if event_handler:
                event_handler.process(event)
        except:
            tyk.log_error("Can't dispatch, error:")

    def reload(self):
        tyk.log("Reloading event handlers and middlewares.", "info")
        self.purge_event_handlers()
        self.load_event_handlers()
        self.load_middlewares()
