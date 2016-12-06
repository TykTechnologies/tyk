from tyk.decorators import Event

@Event
def my_handler(event, spec):
    print("-- my_handler:")
    print(" Event:", event)
    print(" Spec:", spec)
