import imp, sys, os, inspect
from gateway import TykGateway as tyk

class MiddlewareLoader():
    def __init__(self, mw=None):
        self.mw = mw
        self.bundle_root_path = mw.bundle_root_path

    def is_local_import(self, stack):
      # Inspect the stack and verify if the "import" call is local (direct call from middleware code) or not:
      is_local = False
      for fr in stack:
        if fr[3] != "<module>":
          continue
        if self.base_path not in fr[1]:
          break
        is_local = True
      return is_local

    def find_module(self, module_name, package_path):
      module_filename = "{0}.py".format(module_name)
      self.base_path = self.mw.middleware_id
      self.module_path = os.path.join(self.bundle_root_path, self.base_path, module_filename)

      s = inspect.stack()
      if not self.is_local_import(s):
        return None
  
      if not os.path.exists(self.module_path):
        error_msg = "Your bundle doesn't contain '{0}'".format(module_name)
        tyk.log(error_msg, "error")
        return None
      return self

    def load_module(self, module_name):
      module = None
      with open(self.module_path, 'rb') as fp:
        module = imp.load_module(module_name, fp, self.module_path, ('.py', 'rb', imp.PY_SOURCE))
      sys.modules[module_name] = module
      self.mw.imported_modules.append(module_name)
      return module
