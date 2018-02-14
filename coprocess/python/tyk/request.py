class TykCoProcessRequest():
    def __init__(self, request):
        self.object = request

    def add_header(self, key, value):
        self.object.set_headers[key] = value

    def delete_header(self, key):
        self.object.delete_headers.append(key)

    def add_param(self, key, value):
        self.object.add_params[key] = value

    def delete_param(self, key):
        self.object.delete_params.append(key)

    def get_header(self, key):
        if key in self.object.headers:
            return self.object.headers[key]
        else:
            return None
