# Coprocess (gRPC)

This feature makes it possible to write Tyk middleware using a [gRPC](http://www.grpc.io/) backend. gRPC is a very interesting framework that has official support for many languages: C++, Java, Python, Go, Ruby, C#, Node.JS, Java, Objective C & PHP.

The Tyk Coprocess feature uses Protocol Buffers for dispatching messages (mostly requests and events), this makes it easier to connect Tyk to a gRPC server (which is based on Protocol Buffers too), it works by specifying a [gRPC service definition](../proto/coprocess_object.proto) that covers the dispatcher logic:

```
service Dispatcher {
  rpc Dispatch (Object) returns (Object) {}
  rpc DispatchEvent (Event) returns (EventReply) {}
}
```

## gRPC backend

A very simple use case is as follows: you write a gRPC server in a language of your choice, using the Tyk's Protocol Buffer definitions.

When Tyk starts it performs a connection to your gRPC server (this is specified as a global setting in `tyk.conf`, you could use a UNIX socket -local- or even a TCP connection -over the network-).

When Tyk receives a request, it performs a call to your gRPC server, which is responsible for doing the actual tasks (middleware tasks like transformations or even authentication)

## Global settings

This is a section of `tyk.conf` that will:

* Enable the Coprocess feature.
* Indicate your gRPC server address.

```json
"coprocess_options": {
  "enable_coprocess": true,
  "coprocess_grpc_server": "tcp://127.0.0.1:5555"
},
"enable_bundle_downloader": true,
"bundle_base_url": "http://my-bundle-server.com/bundles/",
"public_key_path": "/path/to/my/pubkey",
```


* `enable_coprocess`: Enables the rich plugins feature.
* `coprocess_grpc_server`: Sets the gRPC server host address. This is only required for gRPC plugins.
* `enable_bundle_downloader`: Enables the bundle downloader.
* `bundle_base_url`: A base URL that will be used to download the bundle, in this example we have "test-bundle" specified in the API settings, Tyk will fetch the following URL: "http://my-bundle-server.com/bundles/test-bundle".
* `public_key_path`: Sets a public key, this is used for verifying signed bundles, you may omit this if unsigned bundles are used.

## API settings

This is a sample configuration that will authenticate your API through a Coprocess (gRPC in this case, see `driver`), and a hook a "pre" middleware.

```json
"enable_coprocess_auth": true,
"custom_middleware": {
  "pre": [
    {
      "name": "MyPreMiddleware",
      "require_session": false
    }
  ],
  "auth_check": {
    "name": "MyAuthCheck"
  },
  "driver": "grpc"
},
```

## Examples (Ruby)

You may find a Ruby sample [here](ruby/sample_server.rb).
