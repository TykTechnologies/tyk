class HandlerDecorator(object):
    def __init__(self, f):
        self.f = f
        return
    def __call__(self, req, sess):
        self.f

class Pre(HandlerDecorator):
    def __call__(self, req, sess):
        return self.f(req, sess)

class Post(HandlerDecorator):
    def __call__(self, req, sess):
        self.f(req, sess)

class PostKeyAuth(HandlerDecorator):
    def __cal__(self, req, sess):
        self.f(req, sess)

def ThisIsNotADecorator():
    pass
