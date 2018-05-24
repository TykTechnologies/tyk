from glob import glob
from os import getcwd, chdir, path
import sys

import tyk
from tyk.middleware import TykMiddleware
from tyk.object import TykCoProcessObject
from tyk.event import TykEvent

from gateway import TykGateway as tyk

class TykDispatcher:
    '''A simple dispatcher'''

    def __init__(self, bundle_root_path):
        tyk.log( "Initializing dispatcher", "info" )
        self.bundle_root_path = bundle_root_path
        self.bundles = []
        self.hook_table = {}

    def find_bundle(self, bundle_id):
        found = None
        for bundle in self.bundles:
            if bundle.bundle_id == bundle_id:
                found = bundle
                break
        return found

    def load_bundle(self, bundle_path):
        path_splits = bundle_path.split('/')
        bundle_id = path_splits[-1]
        bundle = self.find_bundle(bundle_id)
        if not bundle:
            bundle = TykMiddleware(bundle_id, bundle_root_path=self.bundle_root_path)
            self.bundles.append(bundle)
        self.update_hook_table(with_bundle=bundle)

    def update_hook_table(self, with_bundle=None):
        new_hook_table = {}
        # Disable any previous bundle associated with an API:
        if with_bundle:
            # First check if this API exists in the hook table:
            hooks = {}
            if with_bundle.api_id in self.hook_table:
                hooks = self.hook_table[with_bundle.api_id]
            if len(hooks) > 0:
                # Pick the first hook and get the current bundle:
                bundle_in_use = list(hooks.values())[0].middleware
                # If the bundle is already in use, skip the hook table update:
                if bundle_in_use.bundle_id == with_bundle.bundle_id:
                    return
            self.hook_table[with_bundle.api_id] = with_bundle.build_hooks_and_event_handlers()

    def find_hook(self, api_id, hook_name):
        hooks = self.hook_table.get(api_id)
        # TODO: handle this situation and also nonexistent hooks
        if not hooks:
            raise Exception('No hooks defined for API: {0}'.format(api_id))

        hook = hooks.get(hook_name)
        if hook:
            return hook.middleware, hook
        else:
            raise Exception('Hook is not defined: {0}'.format(hook_name))

    def dispatch_hook(self, object_msg):
        try:
            object = TykCoProcessObject(object_msg)
            api_id = object.spec['APIID']
            middleware, hook_handler = self.find_hook(api_id, object.hook_name)
            if hook_handler:
                object = middleware.process(hook_handler, object)
            else:
                tyk.log( "Can't dispatch '{0}', hook is not defined.".format(object.hook_name), "error")
            return object.dump()
        except:
            tyk.log_error( "Can't dispatch, error:" )
            return object_msg

    def dispatch_event(self, event_json):
        try:
            event = TykEvent(event_json)
            api_id = event.spec['APIID']
            middleware, hook_handler = self.find_hook(api_id, event.handler_name)
            middleware.process(hook_handler, event)
        except:
            tyk.log_error( "Can't dispatch: ")

    def reload(self):
        tyk.log( "Reloading event handlers and middlewares.", "info" )
