from tyk.decorators import *
from gateway import TykGateway as tyk

@CustomKeyCheck
def MyKeyCheck(request, session, metadata, spec):
    print("Running MyKeyCheck?")

    print("request:", request)
    print("session:", session)
    print("spec:", spec)

    valid_token = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    request_token = request.get_header('Authorization')

    if request_token == valid_token:
        print("Token is OK")
        session.rate = 1000
        session.per = 1
        metadata['token'] = "mytoken"
    else:
        print("Token is WRONG")
        request.return_overrides = { 'response_code': 401, 'response_error': 'Not authorized (by the Python middleware)' }

    return request, session, metadata
