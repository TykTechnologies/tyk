from tyk.decorators import *
from gateway import TykGateway as tyk

@CustomKeyCheck
def MyKeyCheck(request, session, metadata, spec):
    print("Running MyKeyCheck?")
    print("request:", request)
    print("session:", session)
    print("spec:", spec)
    session.rate = 1000
    session.per = 1
    print("session.__dict__ = ", session.__dict__)
    metadata['token'] = "mytoken"
    return request, session, metadata
