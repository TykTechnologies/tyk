from tyk.decorators import *
from tyk.gateway import TykGateway as tyk

@Pre
def ModifyBody(request, session, spec):
    request['SetHeaders']['SomeHeader'] = 'python'
    tyk.store_data( "cool_key", "cool_value", 300 )
    tyk.trigger_event( "a_middleware_event", "additional_data" )
    request['Body'] = "modified_body=1"
    return request, session

@Post
def AddSomeHeader2(request, session, spec):
    print("middleware#AddSomeheader2")
    print("request = ", request)
    print("session = ", session)
    return request, session

def NotARealHandler():
    pass
