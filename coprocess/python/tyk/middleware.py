from importlib import invalidate_caches as invalidate_caches

from types import ModuleType

import imp, inspect, sys, os, json
from time import sleep

import tyk.decorators as decorators
from tyk.loader import MiddlewareLoader
from gateway import TykGateway as tyk

HandlerDecorators = list( map( lambda m: m[1], inspect.getmembers(decorators, inspect.isclass) ) )

class TykMiddleware:
    def __init__(self, filepath, bundle_root_path=None):
        tyk.log( "Loading module: '{0}'".format(filepath), "info")
        self.filepath = filepath
        self.handlers = {}

        self.bundle_id = filepath
        self.bundle_root_path = bundle_root_path

        self.imported_modules = []
        
        module_splits = filepath.split('_')
        self.api_id, self.middleware_id = module_splits[0], module_splits[1]

        self.module_path = os.path.join(self.bundle_root_path, filepath)
        self.parse_manifest()

        self.mw_path = os.path.join(self.module_path, "middleware.py")

        # Fallback for single file bundles:
        if len(self.manifest['file_list']) == 1:
            self.mw_path = os.path.join(self.module_path, self.manifest['file_list'][0])

        try:
            self.loader = MiddlewareLoader(self)
            sys.meta_path.append(self.loader)
            invalidate_caches()
            self.module = imp.load_source(filepath, self.mw_path)
            self.register_handlers()
            self.cleanup()
        except Exception as e:
            tyk.log_error("Middleware initialization error: {0}".format(e))
            pass

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

    def build_hooks_and_event_handlers(self):
        hooks = {}
        for hook_type in self.handlers:
            for handler in self.handlers[hook_type]:
                handler.middleware = self
                hooks[handler.name] = handler
                tyk.log("Loading hook '{0}' ({1})".format(handler.name, self.filepath), "debug")
        return hooks

    def cleanup(self):
        sys.meta_path.pop()
        for m in self.imported_modules:
            del sys.modules[m]

    def process(self, handler, object):
        handlerType = type(handler)

        if handlerType == decorators.Event:
            handler(object, object.spec)
            return
        elif handler.arg_count == 5:
            md = object.session.metadata
            object.response = handler(object.request, object.response, object.session, md, object.spec)
        elif handler.arg_count == 4:
            md = object.session.metadata
            object.request, object.session, md = handler(object.request, object.session, md, object.spec)
            object.session.metadata.MergeFrom(md)
        elif handler.arg_count == 3:
            object.request, object.session = handler(object.request, object.session, object.spec)
        return object

    def parse_manifest(self):
        manifest_path = os.path.join(self.module_path, "manifest.json")
        with open(manifest_path, 'r') as f:
            self.manifest = json.load(f)
