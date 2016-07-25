from tyk.decorators import *
from tyk.gateway import TykGateway as tyk

@Pre
def AddSomeHeader(request, session):
    request['SetHeaders']['SomeHeader'] = 'python'
    tyk.store_data( "cool_key", "cool_value", 300 )
    return request, session

def NotARealHandler():
    pass
