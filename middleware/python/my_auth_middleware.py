from tyk.decorators import *
from gateway import TykGateway as tyk

from tyk.session import AccessSpec, AccessDefinition, BasicAuthData, JWTData, Monitor

@CustomKeyCheck
def MyAuthCheck(request, session, metadata, spec):
    print("my_auth_middleware: CustomKeyCheck hook")

    print("my_auth_middleware - Request:", request)
    print("my_auth_middleware - Session:", session)
    print("my_auth_middleware - Spec:", spec)

    valid_token = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    request_token = request.get_header('Authorization')

    print("my_auth_middleware - Request Token:", request_token)

    if request_token == valid_token:
        session.rate = 1000.0
        session.per = 1.0

        metadata['token'] = 'mytoken'
    else:
        # Invalid token!
        request.object.return_overrides.response_code = 401
        request.object.return_overrides.response_error = 'Not authorized (Python middleware)'

    return request, session, metadata

@PostKeyAuth
def MyPostKeyAuthMiddleware(request, session, spec):
    print("my_auth_middleware: PostKeyAuth hook")
    return request, session
