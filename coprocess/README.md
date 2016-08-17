# Coprocess - PoC

This feature makes it possible to write Tyk middleware using your favorite languages.

## Python support

[Python](https://www.python.org/) support is an ongoing task, more notes [here](python/README.md).

## Interoperability

This feature implements an in-process message passing mechanism, based on [Protocol Buffers](https://developers.google.com/protocol-buffers/), any supported languages should provide a function to receive, unmarshal and process this kind of messages.

The main interoperability task is achieved by using [cgo](https://golang.org/cmd/cgo/) as a bridge between a supported language -like Python- and the Go codebase.

Your C bridge function must accept and return a `CoProcessMessage` data structure like the one described in [`api.h`](api.h), where `p_data` is a pointer to the serialized data and `length` indicates the length of it.

```c
struct CoProcessMessage {
  void* p_data;
  int length;
};
```

The unpacked data will hold the actual `CoProcessObject` data structure, where `HookType` represents the hook type (see below), `Request` represents the HTTP request and `Session` is the Tyk session data.

The `Spec` field holds the API specification data, like organization ID, API ID, etc.


```go
type CoProcessObject struct {
	HookType string
	Request  CoProcessMiniRequestObject
	Session  SessionState
	Metadata map[string]string
	Spec     map[string]string
}
```

## Coprocess Dispatcher - Hooks

This component is in charge of dispatching your HTTP requests to the custom middlewares, in the right order. The dispatcher follows the standard middleware chain logic and provides a simple mechanism for "hooking" your custom middleware behavior, the supported hooks are:

**Pre:** gets executed before any authentication information is extracted from the header or parameter list of the request.

**Post:** gets executed after the authentication, validation, throttling, and quota-limiting middleware has been executed, just before the request is proxied upstream. Use this to post-process a request before sending it to your upstream API.

**PostKeyAuth:** gets executed right after the autentication process.

**CustomKeyCheck:** gets executed as a custom authentication middleware, instead of the standard ones provided by Tyk. Use this to provide your own authentication mechanism.

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

## Tests

You must use the `coprocess` build tag to run the tests:

```
go test -tags 'coprocess'
go test -run CoProcess -tags 'coprocess'
```

## References

[Trello note](https://trello.com/c/6QNWnF2n/265-coprocess-handlers-middleware-replacements-and-hooks)
