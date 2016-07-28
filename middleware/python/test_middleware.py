from tyk.decorators import *
from tyk.gateway import TykGateway as tyk

@Pre
def ModifyRequest(request, session, spec):
    tyk.store_data( "cool_key", "cool_value", 300 )
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

def NotARealHandler():
    pass
