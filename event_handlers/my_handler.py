from tyk.decorators import Event

@Event
def my_handler(event, spec):
    print("Receiving event", event)
    print("And spec", spec)

print(1)
