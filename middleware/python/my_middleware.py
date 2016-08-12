from tyk.decorators import *
from gateway import TykGateway as tyk

@Pre
def MyPreMiddleware(request, session, spec):
    print("my_middleware: MyPreMiddleware")
    return request, session

@Pre
def AnotherPreMiddleware(request, session, spec):
    print("my_middleware: AnotherPreMiddleware")
    return request, session

@Post
def MyPostMiddleware(request, session, spec):
    print("my_middleware: MyPostMiddleware")
    return request, session
    
