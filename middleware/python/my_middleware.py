from tyk.decorators import *
from gateway import TykGateway as tyk

@Hook
def MyPreMiddleware(request, session, spec):
    print("my_middleware: MyPreMiddleware")
    return request, session

@Hook
def AnotherPreMiddleware(request, session, spec):
    print("my_middleware: AnotherPreMiddleware")
    return request, session

@Hook
def MyPostMiddleware(request, session, spec):
    print("my_middleware: MyPostMiddleware")
    return request, session
