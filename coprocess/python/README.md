# Coprocess (Python)

This feature makes it possible to write Tyk middleware using [Python](https://www.python.org/), the current binding supports Python 3.x.
The purpose of this README is to provide an overview of the architecture and a few implementation notes.

## Usage

You'll need to build Tyk with specific build tags, see build notes below.

Basically `go build -tags 'coprocess python'`.

### Setting up custom Python middleware

The custom middleware should be specified in your API definition file, under `custom_middleware` (see [coprocess_app_sample.json](../../apps/coprocess_app_sample.json)):

```json
"custom_middleware": {
  "pre": [
      {
        "name": "MyPreMiddleware",
        "require_session": false
      }
    ],
  "post": [
    {
        "name": "MyPostMiddleware",
        "require_session": false
    }
  ],
  "driver": "python"
}
```

You can chain multiple hook functions when the hook type is Pre, Post or PostAuthCheck.

Tyk will load all the modules inside `middleware/python`.

The "name" field represents the name of a Python function, a sample Python middleware matching the sample definition above will look like (see [middleware/python](../../middleware/python)):

```python
from tyk.decorators import *

@Pre
def MyPreMiddleware(request, session, spec):
    print("my_middleware: MyPreMiddleware")
    return request, session

@Post
def MyPreMiddleware(request, session, spec):
    print("my_middleware: MyPreMiddleware")
    return request, session
```

### Authenticating an API with Python

See example: https://tyk.io/docs/plugins/supported-languages/rich-plugins/python/custom-auth-python-tutorial/

### Writing events handlers with Python

It's also possible to write a Tyk event listener with Python. The first step is to set a custom event handler inside your API definition (see [coprocess_app_sample_protected.json](../../apps/coprocess_app_sample_protected.json)):

```json
...
"event_handlers": {
  "events": {
    "AuthFailure": [
      {
        "handler_name": "cp_dynamic_handler",
        "handler_meta": {
          "name": "my_handler"
        }
      }
    ]
  }
},
...
```

In the above sample we're setting an event handler for `AuthFailure` events, an event that's triggered everytime a failed authentication occurs.

The `handler_name` must be `cp_dynamic_handler`.

The `name` field inside `handler_meta` refers to a Python function name that can be written inside `event_handlers` (see [event_handlers/my_handler.py](../../event_handlers/my_handler.py)):

```python
from tyk.decorators import Event

@Event
def my_handler(event, spec):
    print("-- my_handler:")
    print(" Event:", event)
    print(" Spec:", spec)
```

This function will be called when the specified event occurs, Tyk will pass a Python object like this:

```json
{  
   "TimeStamp": "2016-08-19 11:13:31.537047694 -0400 PYT",
   "Meta":{  
      "Path":"/coprocess-auth-tyk-api-test/",
      "Origin":"127.0.0.1",
      "Message":"Auth Failure",
      "OriginatingRequest":"R0VUIC9jb3Byb2Nlc3MtYXV0aC10eWstYXBpLXRlc3QvIEhUVFAvMS4xDQpIb3N0OiAxMjcuMC4wLjE6ODA4MA0KVXNlci1BZ2VudDogY3VybC83LjQzLjANCkFjY2VwdDogKi8qDQpBdXRob3JpemF0aW9uOiAxDQoNCg==",
      "Key":""
   },
   "Type": "AuthFailure"
}
```

The above handler can be tested by sending a HTTP request to the protected Coprocess API, with an invalid authorization header:

```
curl http://127.0.0.1:8080/coprocess-auth-tyk-api-test/ -H 'Authorization: invalidtoken'
```

## Build requirements

* [Python 3.x](https://www.python.org/)
* [Go](https://golang.org)
* [Cython](http://cython.org/) (required if you need to modify and re-compile the gateway API binding)
* [protobuf](https://pypi.python.org/pypi/protobuf/3.20.2) (Python module): `pip3 install protobuf==3.20.2`
* [grpc](https://www.grpc.io/) (gRPC module): `pip3 install grpcio`

## Build steps

To build Tyk with the Coprocess + Python support, use:

```
go build -tags 'coprocess python'
```

To compile the gateway API binding (assuming you're on the repository root):

```sh
cd coprocess/python
./cythonize gateway
```

This will "cythonize" `gateway.pyx`, generating `gateway.c` and `gateway.h`.

To compile some other binding (where `mybinding.pyx` is your Cython input file):

```sh
cd coprocess/python
./cythonize mybinding
```

[cythonize](cythonize) is a helper script for compiling Python source files with Cython and patching the resulting source with the specific build tags used by this Coprocess feature.
This is important in order to keep Tyk build-able when a standard build is needed (and make the Go compiler ignore C binding files based on the specified build tags).

The top of a standard Cython binding file will look like this:
```
/* Generated by Cython 0.24.1 */

/* BEGIN: Cython Metadata
{
    "distutils": {
        "depends": []
    },
    "module_name": "gateway"
}
END: Cython Metadata */
```

After running `cythonize` the binding will have the correct build tags, and will be ignored if you don't build Tyk with these (`go build -tags 'coprocess python'`):

```
// +build coprocess
// +build python

/* Generated by Cython 0.24.1 */

/* BEGIN: Cython Metadata
{
    "distutils": {
        "depends": []
    },
    "module_name": "gateway"
}
END: Cython Metadata */
```

After re-compiling a binding, the C source code will change and you may want to build Tyk again.

## CPython

[Python](https://www.python.org/) has a very popular and well-documented [C API](https://docs.python.org/3/c-api/index.html), this coprocess feature makes a heavy use of it.

## Built-in modules

All the standard Python modules are available and it's also possible to load additional ones, if you add them to your local Python installation (for example, using pip).

### Coprocess Gateway API

There's a Python binding for the [Coprocess Gateway API](../README.md), this is written using the Cython syntax, it's basically a single file: [`gateway.pyx`](tyk/gateway.pyx).

This binding exposes some functions, like a storage handler that allows you to get/set Redis keys:

```python
from tyk.decorators import *
from gateway import TykGateway as tyk

@Pre
def SetKeyOnRequest(request, session, spec):
    tyk.store_data( "my_key", "expiring_soon", 15 )
    val = tyk.get_data("cool_key")
    return request, session
```

### Cython bindings

Cython takes a `.pyx` file and generates a C source file (`.c`) with its corresponding header (`.h`), after this process, we use these two files as part of the `cgo` build process. This approach has been used as an alternative to `cffi`, which introduced an additional step into the setup, requiring the user to install the module first.

So in practice, we don't use the `.pyx` files directly (and they aren't required at runtime!). When the build process is over, the bindings are part of the Tyk binary and can be loaded and accessed from Go code.

The bindings [declare an initialization function](tyk/gateway.h) that should be called after the Python interpreter is invoked, this will load the actual module and make it possible to import it using `import mymodule`. This is how [`gateway.pyx`](tyk/gateway.pyx) and its functions become available.

### Middleware and wrappers

There are [quick wrappers](tyk/) for the HTTP request and session objects, written in Python, the idea is to provide an idiomatic way of writing middleware:

```python
from tyk.decorators import *

@Pre
def AppendHeader(request, session, spec):
    request.add_header("custom_header", "custom_value")
    return request, session
```

The decorators provide a simple way of indicating when it's the right moment to execute your handlers, a handler that is decorated with `Pre` will be called before any authentication occurs, `Post` will occur after authentication and will have access to the `session` object.
You may find more information about Tyk middleware [here](https://tyk.io/docs/tyk-api-gateway-v1-9/javascript-plugins/middleware-scripting/).
