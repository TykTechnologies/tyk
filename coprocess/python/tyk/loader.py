import imp, sys, os
from gateway import TykGateway as tyk

class MiddlewareLoader():
    def __init__(self, mw=None):
        self.mw = mw
        self.bundle_root_path = mw.bundle_root_path

    def find_module(self, module_name, package_path):
      module_filename = "{0}.py".format(module_name)
      self.base_path = "{0}_{1}".format(self.mw.api_id, self.mw.middleware_id)
      self.module_path = os.path.join(self.bundle_root_path, self.base_path, module_filename)
      if not os.path.exists(self.module_path):
        error_msg = "Your bundle doesn't contain '{0}'".format(module_name)
        tyk.log(error_msg, "error")
        return None
      return self

    def load_module(self, module_name):
      module = imp.load_module(module_name, self.module_path)

      sys.modules[module_name] = module
      self.mw.imported_modules.append(module_name)

      return module