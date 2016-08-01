from tyk.decorators import *
from gateway import TykGateway as tyk

@Pre
def ModifyRequest(request, session, spec):
    print("about to store cool_key!")
    tyk.store_data( "cool_key", "not_so_cool", 300 )
    print("about to fetch cool_key")
    val = tyk.get_data("cool_key")
    print("val = ", val)
    tyk.store_data( "expire_soon", "not_so_cool", 5 )
    tyk.trigger_event( "a_middleware_event", "additional_data" )

    request.add_header("custom_header", "custom_value")
    request.delete_header("Accept")

    request.add_param("param_a", "value_a")
    request.delete_param("param_remove")

    return request, session

@Post
def AddSomeHeader(request, session, spec):
    print("session = ", session, session.__dict__)
    print(session.allowance)

    return request, session

@PostKeyAuth
def Something(request, session, spec):
    print("post key auth?")

    return request, session

def NotARealHandler():
    pass
