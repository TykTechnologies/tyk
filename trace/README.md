Closes #187

This is initial implementation of the opentracing support


# What is traced
The whole point behind tracing is tracking a request as it is being propagated
across process boundaries, so we have two kinds of traces that are covered here.

- [x] The gateway api . This is endpoints under the `/tyk` endpoints.
- [x] The proxy api. This is all loaded specs by the gateway.

The level of details and information covered varies between those two because
of different requirements.

# Tracer clients

These are servers where the collected traces are sent.

- [x]  [appdash](https://github.com/sourcegraph/appdash)
- [ ] [jaeger](https://www.jaegertracing.io/)

# How tracing works in the gateway

This is only PoC . So it is not fine tuned to handle all cases. We are only tracing the amount of time taken to complete each request/response roundtrip. This includes all middlewares applied in the process (for the request and response).

TODO: write more about this as I grok the gateway internals

# Configuring

To configure tracing, a new setting `tracing` must be added to the tyk
configuration. The configuration options are like this,

```json
{
    ... the rest of tyk config

    "tracing":{
        "name":"appdash",
        "enabled":true,
        "options":{
            "conn":"appdash:7701"
        }
    }
}
```

- `name` is the name of the tracer, for now only `appdash` is implemented for testing. `jaeger` or `zipkin` will be nice for production.
- `enabled` : when false then tracing will be disabled.
- `options`: key/value pairs which are used to configure the tracer in our example we set `conn` which is needed for the appdash remote collector.