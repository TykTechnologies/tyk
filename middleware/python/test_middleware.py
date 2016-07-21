from tyk.decorators import *

@Pre
def AddSomeHeader(request, session):
    # request['Body'] = 'tyk=python'
    request['SetHeaders']['SomeHeader'] = 'python2'
    return request, session

def NotARealHandler():
    pass
