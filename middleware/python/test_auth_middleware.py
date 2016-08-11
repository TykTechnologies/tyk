from tyk.decorators import *
from gateway import TykGateway as tyk

@CustomKeyCheck
def MyKeyCheck(request, session, metadata, spec):
    print("test_auth_middleware: MyKeyCheck")

    print("test_auth_middleware - Request:", request)
    print("test_auth_middleware - Session:", session)
    print("test_auth_middleware - Spec:", spec)

    valid_token = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    request_token = request.get_header('Authorization')

    print("test_auth_middleware - Request Token:", request_token)

    if request_token == valid_token:
        print("test_auth_middleware: Valid token")
        session.object.rate = 1000.0
        session.object.per = 1.0
        metadata['token'] = 'mytoken'
    else:
        print("test_auth_middleware: Invalid token")
        request.__object__.return_overrides.response_code = 401
        request.__object__.return_overrides.response_error = 'Not authorized (Python middleware)'

    return request, session, metadata
