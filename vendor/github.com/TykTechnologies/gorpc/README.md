gorpc
=====

Simple, fast and scalable golang RPC library for high load.


Gorpc provides the following features useful for highly loaded projects
with RPC:

* It minimizes the number of connect() syscalls by pipelining request
  and response messages over a single connection.

* It minimizes the number of send() syscalls by packing as much
  as possible pending requests and responses into a single compressed buffer
  before passing it into send() syscall.

* It minimizes the number of recv() syscalls by reading and buffering as much
  as possible data from the network.

* It supports RPC batching, which allows preparing multiple requests and sending
  them to the server in a single batch.

These features help the OS minimizing overhead (CPU load, the number of
TCP connections in TIME_WAIT and CLOSE_WAIT states, the number of network
packets and the amount of network bandwidth) required for RPC processing under
high load.


Gorpc additionally provides the following features missing
in [net/rpc](http://golang.org/pkg/net/rpc/):

* Client automatically manages connections and automatically reconnects
  to the server on connection errors.
* Client supports response timeouts out of the box.
* Client supports RPC batching out of the box.
* Client detects stuck servers and immediately returns error to the caller.
* Client supports fast message passing to the Server, i.e. requests
  without responses.
* Both Client and Server provide network stats and RPC stats out of the box.
* Commonly used RPC transports such as TCP, TLS and unix socket are available
  out of the box.
* RPC transport compression is provided out of the box.
* Server provides graceful shutdown out of the box.
* Server supports RPC handlers' councurrency throttling out of the box.
* Server may pass client address to RPC handlers.
* Server gracefully handles panic in RPC handlers.
* Dispatcher accepts functions as RPC handlers.
* Dispatcher supports registering multiple receiver objects of the same type
  under distinct names.
* Dispatcher supports RPC handlers with zero, one (request) or two (client
  address and request) arguments and zero, one (either response or error)
  or two (response, error) return values.


Dispatcher API provided by gorpc allows easily converting usual functions
and/or struct methods into RPC versions on both client and server sides.
See [Dispatcher examples](http://godoc.org/github.com/valyala/gorpc#Dispatcher)
for more details.


By default TCP connections are used as underlying gorpc transport.
But it is possible using arbitrary underlying transport - just provide custom
implementations for Client.Dial and Server.Listener.
RPC authentication, authorization and encryption can be easily implemented
via custom underlying transport and/or via OnConnect callbacks.
Currently gorpc provides TCP, TLS and unix socket transport out of the box.


Currently gorpc with default settings is successfully used in highly loaded
production environment serving up to 40K qps. Switching from http-based rpc
to gorpc reduced required network bandwidth from 300 Mbit/s to 24 Mbit/s.


Docs
====

See http://godoc.org/github.com/valyala/gorpc .


Usage
=====

Server:
```go
s := &gorpc.Server{
	// Accept clients on this TCP address.
	Addr: ":12345",

	// Echo handler - just return back the message we received from the client
	Handler: func(clientAddr string, request interface{}) interface{} {
		log.Printf("Obtained request %+v from the client %s\n", request, clientAddr)
		return request
	},
}
if err := s.Serve(); err != nil {
	log.Fatalf("Cannot start rpc server: %s", err)
}
```

Client:
```go
c := &gorpc.Client{
	// TCP address of the server.
	Addr: "rpc.server.addr:12345",
}
c.Start()

resp, err := c.Call("foobar")
if err != nil {
	log.Fatalf("Error when sending request to server: %s", err)
}
if resp.(string) != "foobar" {
	log.Fatalf("Unexpected response from the server: %+v", resp)
}
```

Both client and server collect connection stats - the number of bytes
read / written and the number of calls / errors to send(), recv(), connect()
and accept(). This stats is available at Client.Stats and Server.Stats.

See tests for more usage examples.
