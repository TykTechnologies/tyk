from inspect import getfullargspec


class HandlerDecorator(object):
    def __init__(self, f):
        self.name = f.__name__
        self.f = f

    def __call__(self, req, sess, spec):
        self.f


class Hook(object):
    def __init__(self, f):
        self.name = f.__name__
        self.f = f
        self.arg_count = len(getfullargspec(f)[0])

    def __call__(self, *args, **kwargs):
        if self.arg_count == 3:
            return self.f(args[0], args[1], args[2])
        if self.arg_count == 4:
            return self.f(args[0], args[1], args[2], args[3])
        if self.arg_count == 5:
            return self.f(args[0], args[1], args[2], args[3], args[4])


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
        self.name = f.__name__

    def __call__(self, req, sess, metadata, spec):
        return self.f(req, sess, metadata, spec)


class Event(object):
    def __init__(self, f):
        self.name = f.__name__
        self.f = f

    def __call__(self, event, spec):
        self.f(event, spec)


def ThisIsNotADecorator():
    pass
