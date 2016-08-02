class HandlerDecorator(object):
    def __init__(self, f):
        self.f = f
        return
    def __call__(self, req, sess, spec):
        self.f

class Pre(HandlerDecorator):
    def __call__(self, req, sess, spec):
        return self.f(req, sess, spec)

class Post(HandlerDecorator):
    def __call__(self, req, sess, spec):
        return self.f(req, sess, spec)

class PostKeyAuth(HandlerDecorator):
    def __call__(self, req, sess, spec):
        return self.f(req, sess, spec)

class CustomKeyCheck():
    def __init__(self, f):
        self.f = f
        return
    def __call__(self, req, sess, metadata, spec):
        return self.f(req, sess, metadata)

def ThisIsNotADecorator():
    pass
