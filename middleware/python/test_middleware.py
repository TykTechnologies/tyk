from tyk.decorators import *
from gateway import TykGateway as tyk

@Pre
def CallTykAPI(request, session, spec):
    print("test_middleware: CallTykAPI")

    print("test_middleware: tyk.store_data")
    tyk.store_data( "cool_key", "cool_value", 300 )

    print("test_middleware: tyk.get_data")
    print("test_middleware: ", tyk.get_data("cool_key") )

    print("test_middleware: tyk.trigger_event")
    tyk.trigger_event( "a_middleware_event", "additional_data" )

    # TODO: what to do when the function doesn't return (or returns wrong values)?
    return request, session

@Pre
def ModifyRequest(request, session, spec):
    print("test_middleware: ModifyRequest")

    request.add_header("custom_header", "custom_value")
    request.delete_header("Accept")

    request.add_param("param_a", "value_a")
    request.delete_param("param_remove")

    return request, session

@Post
def PrintSession(request, session, spec):
    print("test_middleware: PrintSession")
    # print("session = ", session, session.object)
    # print(session.allowance)

    return request, session

@PostKeyAuth
def MyPostKeyAuthMiddleware(request, session, spec):
    print("test_middleware: PostKeyAuth")
    print("session object:")
    print(session)

    return request, session

def NotARealHandler():
    pass
