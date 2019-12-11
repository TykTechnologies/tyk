# New Relic Go Agent [![GoDoc](https://godoc.org/github.com/newrelic/go-agent?status.svg)](https://godoc.org/github.com/newrelic/go-agent)

## Description

The New Relic Go Agent allows you to monitor your Go applications with New
Relic.  It helps you track transactions, outbound requests, database calls, and
other parts of your Go application's behavior and provides a running overview of
garbage collection, goroutine activity, and memory use.

All pull requests will be reviewed by the New Relic product team. Any questions or issues should be directed to our [support
site](http://support.newrelic.com/) or our [community
forum](https://discuss.newrelic.com).

## Requirements

Go 1.3+ is required, due to the use of http.Client's Timeout field.

Linux, OS X, and Windows (Vista, Server 2008 and later) are supported.

## Integrations

The following [_integration packages](https://godoc.org/github.com/newrelic/go-agent/_integrations)
extend the base [newrelic](https://godoc.org/github.com/newrelic/go-agent) package
to support the following frameworks and libraries.
Frameworks and databases which don't have an integration package may still be
instrumented using the [newrelic](https://godoc.org/github.com/newrelic/go-agent)
package primitives.  Specifically, more information about instrumenting your database using
these primitives can be found
[here](https://github.com/newrelic/go-agent/blob/master/GUIDE.md#datastore-segments).

<!---
NOTE!  When updating the table below, be sure to update the docs site version too:
https://docs.newrelic.com/docs/agents/go-agent/get-started/go-agent-compatibility-requirements
-->

| Project | Integration Package |  |
| ------------- | ------------- | - |
| [aws/aws-sdk-go](https://github.com/aws/aws-sdk-go) | [_integrations/nrawssdk/v1](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrawssdk/v1) | Instrument outbound calls made using Go AWS SDK |
| [aws/aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) | [_integrations/nrawssdk/v2](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrawssdk/v2) | Instrument outbound calls made using Go AWS SDK v2 |
| [labstack/echo](https://github.com/labstack/echo) | [_integrations/nrecho](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrecho) | Instrument inbound requests through the Echo framework |
| [gin-gonic/gin](https://github.com/gin-gonic/gin) | [_integrations/nrgin/v1](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgin/v1) | Instrument inbound requests through the Gin framework |
| [gorilla/mux](https://github.com/gorilla/mux) | [_integrations/nrgorilla/v1](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgorilla/v1) | Instrument inbound requests through the Gorilla framework |
| [julienschmidt/httprouter](https://github.com/julienschmidt/httprouter) | [_integrations/nrhttprouter](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrhttprouter) | Instrument inbound requests through the HttpRouter framework |
| [aws/aws-lambda-go](https://github.com/aws/aws-lambda-go) | [_integrations/nrlambda](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlambda) | Instrument AWS Lambda applications |
| [sirupsen/logrus](https://github.com/sirupsen/logrus) | [_integrations/nrlogrus](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlogrus) | Send agent log messages to Logrus |
| [mgutz/logxi](https://github.com/mgutz/logxi) | [_integrations/nrlogxi/v1](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlogxi/v1) | Send agent log messages to Logxi |
| [uber-go/zap](https://github.com/uber-go/zap) | [_integrations/nrzap](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrzap) | Send agent log messages to Zap |
| [pkg/errors](https://github.com/pkg/errors) | [_integrations/nrpkgerrors](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrpkgerrors) | Wrap pkg/errors errors to improve stack traces and error class information |
| [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql) | [_integrations/nrmysql](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrmysql) | Instrument MySQL driver |
| [lib/pq](https://github.com/lib/pq) | [_integrations/nrpq](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrpq) | Instrument PostgreSQL driver |
| [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3) | [_integrations/nrsqlite3](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrsqlite3) | Instrument SQLite driver |
| [google.golang.org/grpc](https://github.com/grpc/grpc-go) | [_integrations/nrgrpc](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgrpc) | Instrument gRPC servers and clients |
| [micro/go-micro](https://github.com/micro/go-micro) | [_integrations/nrmicro](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrmicro) | Instrument servers, clients, publishers, and subscribers through the Micro framework |
| [nats-io/nats.go](https://github.com/nats-io/nats.go) | [_integrations/nrnats](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrnats) | Instrument publishers and subscribers using the NATS client |
| [nats-io/stan.go](https://github.com/nats-io/stan.go) | [_integrations/nrstan](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrstan) | Instrument publishers and subscribers using the NATS streaming client |


These integration packages must be imported along
with the [newrelic](https://godoc.org/github.com/newrelic/go-agent) package, as shown in this
[nrgin example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrgin/v1/example/main.go).

## Getting Started

Follow the steps in [GETTING_STARTED.md](GETTING_STARTED.md) to instrument your
application.

## Runnable Example

[examples/server/main.go](./examples/server/main.go) is an example that will
appear as "Example App" in your New Relic applications list.  To run it:

```
env NEW_RELIC_LICENSE_KEY=__YOUR_NEW_RELIC_LICENSE_KEY__LICENSE__ \
    go run examples/server/main.go
```

Some endpoints exposed are [http://localhost:8000/](http://localhost:8000/)
and [http://localhost:8000/notice_error](http://localhost:8000/notice_error)

## Support

You can find more detailed documentation [in the guide](GUIDE.md) and on
[the New Relic Documentation site](https://docs.newrelic.com/docs/agents/go-agent).

If you can't find what you're looking for there, reach out to us on our [support
site](http://support.newrelic.com/) or our [community
forum](https://discuss.newrelic.com) and we'll be happy to help you.

Find a bug?  Contact us via [support.newrelic.com](http://support.newrelic.com/),
or email support@newrelic.com.
