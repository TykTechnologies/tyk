from tyk.decorators import Event

@Event
def my_handler(event, spec):
    print("-- my_handler:")
    print(" Event:", event, "\n")
    print(" Spec:", spec, "\n")

def some_other_stuff():
    pass

print(1)
