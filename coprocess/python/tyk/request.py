class TykCoProcessRequest():
    def __init__(self, request):
        self.__object__ = request
    def add_header(self, key, value):
        self.__object__.set_headers[key] = value
    def delete_header(self, key):
        self.__object__.delete_headers.append(key)
    def add_param(self, key, value):
        self.__object__.add_params[key] = value
    def delete_param(self, key):
        self.__object__.delete_params.append(key)
    def get_header(self, key):
        if key in self.__object__.headers:
            return self.__object__.headers[key]
        else:
            return None
