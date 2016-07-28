from tyk.decorators import *
from tyk.gateway import TykGateway as tyk

@CustomKeyCheck
def MyKeyCheck(request, session, spec):
    print("Running MyKeyCheck?")
    return request, session
