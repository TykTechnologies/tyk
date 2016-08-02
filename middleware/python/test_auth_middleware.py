from tyk.decorators import *
from gateway import TykGateway as tyk

@CustomKeyCheck
def MyKeyCheck(request, session, spec):
    print("Running MyKeyCheck?")
    print("request:", request)
    print("session:", session)
    print("spec:", spec)
    return request, session
