from tyk.decorators import *
from gateway import TykGateway as tyk

from tyk.session import AccessSpec, AccessDefinition, BasicAuthData, JWTData, Monitor

@CustomKeyCheck
def MyAuthCheck(request, session, metadata, spec):
    print("test_auth_middleware: MyKeyCheck")

    print("test_auth_middleware - Request:", request)
    print("test_auth_middleware - Session:", session)
    print("test_auth_middleware - Spec:", spec)

    valid_token = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    request_token = request.get_header('Authorization')

    print("test_auth_middleware - Request Token:", request_token)

    if request_token == valid_token:
        print("test_auth_middleware: Valid token")
        session.rate = 1000.0
        session.per = 1.0

        spec = AccessSpec( url="http://test_url", methods=["GET", "POST"])
        definition = AccessDefinition( api_name="My API", api_id="api_01", allowed_urls=[spec])
        session.access_rights["key"].CopyFrom(definition)

        print("Returning session:", session)

        metadata['token'] = 'mytoken'
    else:
        print("test_auth_middleware: Invalid token")
        request.object.return_overrides.response_code = 401
        request.object.return_overrides.response_error = 'Not authorized (Python middleware)'

    return request, session, metadata
