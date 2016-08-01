# Coprocess - PoC

## Build notes

It's possible to use a [build tag](https://golang.org/pkg/go/build/#hdr-Build_Constraints):

```
go build -tags 'coprocess python'
```

```
go build -tags 'coprocess somelanguage'
```

Each language should implement a ```CoProcessInit``` function, this will be called from the main function when the ```coprocess``` build tag is used.

Using the ```coprocess``` build tag with no language tag will fail.

A standard build is still possible:

```
go build
```

```coprocess_dummy.go``` provides a dummy ```CoProcessInit``` function that will be called if you perform a standard Tyk build. This file will be ignored when using the ```coprocess``` build tag, as we expect it to be implemented by a language.

## Python support

[Python](https://www.python.org/) support is an ongoing task, more notes [here](python/README.md).

## Coprocess Gateway API

[`coprocess_api.go`](../coprocess_api.go) provides a bridge between the gateway API and C, any function that needs to be exported should have the `export` keyword:

```go
//export TykTriggerEvent
func TykTriggerEvent( CEventName *C.char, CPayload *C.char ) {
  eventName := C.GoString(CEventName)
  payload := C.GoString(CPayload)

  FireSystemEvent(tykcommon.TykEvent(eventName), EventMetaDefault{
    Message: payload,
  })
}
```

You should also expect a header file declaration of this function in [`api.h`](api.h), like this:

```c
#ifndef TYK_COPROCESS_API
#define TYK_COPROCESS_API
extern void TykTriggerEvent(char* event_name, char* payload);
#endif
```

The language binding will include this header file (or declare the function inline) and perform the necessary steps to call it with the appropriate arguments (like a `ffi` mechanism could do). As a reference, this is how this could be achieved if you're building a [Cython](http://cython.org/) module:

```python
cdef extern:
  void TykTriggerEvent(char* event_name, char* payload);

def call():
  event_name = 'my event'.encode('utf-8')
  payload = 'my payload'.encode('utf-8')
  TykTriggerEvent( event_name, payload )
```

## References

[Trello note](https://trello.com/c/6QNWnF2n/265-coprocess-handlers-middleware-replacements-and-hooks)
