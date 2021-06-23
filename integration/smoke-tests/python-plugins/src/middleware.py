from tyk.decorators import *
from gateway import TykGateway as tyk

@Hook
def MyFooBarMiddleware(request, session, metadata, spec):
  request.add_header('Foo', 'Bar')
  return request, session, metadata
