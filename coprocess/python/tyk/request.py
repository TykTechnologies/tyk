class TykCoProcessRequest:
    def __init__(self, request):
        self.__dict__ = request
    def add_header(self, key, value):
        self.SetHeaders[key] = value
    def delete_header(self, key):
        self.DeleteHeaders.append(key)
    def add_param(self, key, value):
        self.AddParams[key] = value
    def delete_param(self, key):
        self.DeleteParams.append(key)
    def get_header(self, key):
        if key in self.Headers:
            return self.Headers[key][0]
        else:
            return None
