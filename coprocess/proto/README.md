# Tyk gRPC protobuf documentation

gRPC is a very powerful framework for RPC communication across different languages.
It was created by Google and makes heavy use of HTTP2 capabilities and the Protocol
Buffers serialisation mechanism.

Protocol Buffers are used for dispatching and exchanging requests between Tyk and your
gRPC plugins. Protocol Buffers can be versioned using the conventions outlined
here. The protocol definitions and bindings provided by Tyk should be used in order
for the communication to be successful.

This website defines the protobuf interface that a gRPC plugin should
implement.

Tyk Gateway can be configured to act as a client to a gRPC server. With this approach
the middleware operations are performed by the gRPC server, externally to the Tyk
Gateway process. An example is illustrated below:

![Example gRPC plugin architecture](@ref grpc-example-architecture.webp){html: width=75%}

1. Tyk Gateway receives a HTTP request, which it forwards to the gRPC server.
2. The gRPC server performs the middleware operations, e.g. modifying the request object.
3. The gRPC server sends the request back to Tyk.
4. Tyk proxies the request to your upstream API.

Tyk has built-in support for gRPC backends, enabling you to build plugins using
any of the gRPC supported languages. At the time of writing, the following languages
are supported: C++, Java, Objective-C, Python, Ruby, Go, C# and Node.JS.

You may re-use the bindings that were generated for our samples. In case you find it
necessary, or you don’t find a sample that uses your target language, you may generate
the bindings yourself. The Protocol Buffers and gRPC documentation provide specific
requirements and instructions for each language.

This website documents the protobuf Services and Messages for the gRPC server.

## Generating the docs

To generate the documentation for the gRPC protobuf files, firstly ensure the following pre-requisites are installed:

- [Task](https://taskfile.dev/installation/)
- [Doxygen](https://www.doxygen.nl/index.html)

Subsequently, issue the following command:

```bash
task docs
```

This will generate a *html* and *xml* output folders. The documentation for the Tyk gRPC protobuf files is available within the *index.html* file of the *html* folder.

## Generating the gRPC bindings

To generate the gRPC bindings for Go, Python and Ruby, firstly ensure that the following pre-requisite is installed:

- [Task](https://taskfile.dev/installation/)

Subsequently, issue the following command:

```bash
task generate
```

This will install module dependencies for Go and Python. The source bindings will be generated in the *coprocess/bindings* folder of your [local Tyk repository](https://github.com/TykTechnologies/tyk)
