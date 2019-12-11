# New Relic Go Agent Guide

* [Installation](#installation)
* [Config and Application](#config-and-application)
* [Logging](#logging)
* [Transactions](#transactions)
* [Segments](#segments)
  * [Datastore Segments](#datastore-segments)
  * [External Segments](#external-segments)
* [Attributes](#attributes)
* [Tracing](#tracing)
  * [Distributed Tracing](#distributed-tracing)
  * [Cross-Application Tracing](#cross-application-tracing)
  * [Tracing instrumentation](#tracing-instrumentation)
    * [Getting Tracing Instrumentation Out-of-the-Box](#getting-tracing-instrumentation-out-of-the-box)
    * [Manually Implementing Distributed Tracing](#manually-implementing-distributed-tracing)
* [Distributed Tracing](#distributed-tracing)
* [Custom Metrics](#custom-metrics)
* [Custom Events](#custom-events)
* [Request Queuing](#request-queuing)
* [Error Reporting](#error-reporting)
  * [NoticeError](#noticeerror)
    * [Advanced NoticeError Use](#advanced-noticeerror-use)
  * [Panics](#panics)
  * [Error Response Codes](#error-response-codes)
* [Naming Transactions and Metrics](#naming-transactions-and-metrics)
* [Browser](#browser)
* [For More Help](#for-more-help)

## Installation

Installing the Go Agent is the same as installing any other Go library.  The
simplest way is to run:

```
go get github.com/newrelic/go-agent
```

Then import the `github.com/newrelic/go-agent` package in your application.

## Config and Application

* [config.go](config.go)
* [application.go](application.go)

In your `main` function or in an `init` block:

```go
config := newrelic.NewConfig("Your Application Name", "__YOUR_NEW_RELIC_LICENSE_KEY__")
app, err := newrelic.NewApplication(config)
```

Find your application in the New Relic UI.  Click on it to see the Go runtime
page that shows information about goroutine counts, garbage collection, memory,
and CPU usage.

If you are working in a development environment or running unit tests, you may
not want the Go Agent to spawn goroutines or report to New Relic.  You're in
luck!  Set the config's `Enabled` field to false.  This makes the license key
optional.

```go
config := newrelic.NewConfig("Your Application Name", "")
config.Enabled = false
app, err := newrelic.NewApplication(config)
```

## Logging

The agent's logging system is designed to be easily extensible.  By default, no
logging will occur.  To enable logging, assign the `Config.Logger` field to
something implementing the
[Logger](https://godoc.org/github.com/newrelic/go-agent#Logger) interface.  Two
[Logger](https://godoc.org/github.com/newrelic/go-agent#Logger) implementations
are included:
[NewLogger](https://godoc.org/github.com/newrelic/go-agent#NewLogger), which
logs at info level, and
[NewDebugLogger](https://godoc.org/github.com/newrelic/go-agent#NewDebugLogger)
which logs at debug level.

To log at debug level to standard out, set:

```go
cfg.Logger = newrelic.NewDebugLogger(os.Stdout)
```

To log at info level to a file, set:

```go
w, err := os.OpenFile("my_log_file", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
if nil == err {
  cfg.Logger = newrelic.NewLogger(w)
}
```

Popular logging libraries `logrus` and `logxi` are supported by integration packages:

* [_integrations/nrlogrus](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlogrus)
* [_integrations/nrlogxi/v1](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlogxi/v1)

## Transactions

* [transaction.go](transaction.go)
* [Naming Transactions](#naming-transactions-and-metrics)
* [More info on Transactions](https://docs.newrelic.com/docs/apm/applications-menu/monitoring/transactions-page)

Transactions time requests and background tasks.  Each transaction should only
be used in a single goroutine.  Start a new transaction when you spawn a new
goroutine.

The simplest way to create transactions is to use
`Application.StartTransaction` and `Transaction.End`.

```go
txn := app.StartTransaction("transactionName", responseWriter, request)
defer txn.End()
```

If the response writer is provided when calling `StartTransaction`, you can
then use `txn.WriteHeader` as a drop in replacement for the standard library's
[`http.ResponseWriter.WriteHeader`](https://golang.org/pkg/net/http/#ResponseWriter)
function. We strongly recommend doing so, as this both enables cross-application
tracing support and ensures that attributes are added to the
Transaction event capturing the response size and status code.

The response writer and request parameters are optional.  Leave them `nil` to
instrument a background task.

```go
txn := app.StartTransaction("backgroundTask", nil, nil)
defer txn.End()
```

The transaction has helpful methods like `NoticeError` and `SetName`.
See more in [transaction.go](transaction.go).

If you are using [`http.ServeMux`](https://golang.org/pkg/net/http/#ServeMux),
use `WrapHandle` and `WrapHandleFunc`.  These wrappers automatically start and
end transactions with the request and response writer.  See
[instrumentation.go](instrumentation.go).

```go
http.HandleFunc(newrelic.WrapHandleFunc(app, "/users", usersHandler))
```

To access the transaction in your handler, use type assertion on the response
writer passed to the handler.

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
	if txn, ok := w.(newrelic.Transaction); ok {
		txn.NoticeError(errors.New("my error message"))
	}
}
```

## Segments

* [segments.go](segments.go)

Find out where the time in your transactions is being spent!  Each transaction
should only track segments in a single goroutine.

`Segment` is used to instrument functions, methods, and blocks of code. A
segment begins when its `StartTime` field is populated, and finishes when its
`End` method is called.

```go
segment := newrelic.Segment{}
segment.Name = "mySegmentName"
segment.StartTime = newrelic.StartSegmentNow(txn)
// ... code you want to time here ...
segment.End()
```

`StartSegment` is a convenient helper.  It creates a segment and starts it:

```go
segment := newrelic.StartSegment(txn, "mySegmentName")
// ... code you want to time here ...
segment.End()
```

Timing a function is easy using `StartSegment` and `defer`.  Just add the
following line to the beginning of that function:

```go
defer newrelic.StartSegment(txn, "mySegmentName").End()
```

Segments may be nested.  The segment being ended must be the most recently
started segment.

```go
s1 := newrelic.StartSegment(txn, "outerSegment")
s2 := newrelic.StartSegment(txn, "innerSegment")
// s2 must be ended before s1
s2.End()
s1.End()
```

A zero value segment may safely be ended.  Therefore, the following code
is safe even if the conditional fails:

```go
var s newrelic.Segment
if txn, ok := w.(newrelic.Transaction); ok {
	s.StartTime = newrelic.StartSegmentNow(txn),
}
// ... code you wish to time here ...
s.End()
```

### Datastore Segments

Datastore segments appear in the transaction "Breakdown table" and in the
"Databases" page.

* [More info on Databases page](https://docs.newrelic.com/docs/apm/applications-menu/monitoring/databases-slow-queries-page)

Datastore segments are instrumented using
[DatastoreSegment](https://godoc.org/github.com/newrelic/go-agent#DatastoreSegment).
Just like basic segments, datastore segments begin when the `StartTime` field
is populated and finish when the `End` method is called.  Here is an example:

```go
s := newrelic.DatastoreSegment{
	// Product is the datastore type.  See the constants in
	// https://github.com/newrelic/go-agent/blob/master/datastore.go.  Product
	// is one of the fields primarily responsible for the grouping of Datastore
	// metrics.
	Product: newrelic.DatastoreMySQL,
	// Collection is the table or group being operated upon in the datastore,
	// e.g. "users_table".  This becomes the db.collection attribute on Span
	// events and Transaction Trace segments.  Collection is one of the fields
	// primarily responsible for the grouping of Datastore metrics.
	Collection: "users_table",
	// Operation is the relevant action, e.g. "SELECT" or "GET".  Operation is
	// one of the fields primarily responsible for the grouping of Datastore
	// metrics.
	Operation: "SELECT",
}
s.StartTime = newrelic.StartSegmentNow(txn)
// ... make the datastore call
s.End()
```

This may be combined into a single line when instrumenting a datastore call
that spans an entire function call:

```go
s := newrelic.DatastoreSegment{
	StartTime:  newrelic.StartSegmentNow(txn),
	Product:    newrelic.DatastoreMySQL,
	Collection: "my_table",
	Operation:  "SELECT",
}
defer s.End()
```

If you are using the standard library's
[database/sql](https://golang.org/pkg/database/sql/) package with
[MySQL](https://github.com/go-sql-driver/mysql),
[PostgreSQL](https://github.com/lib/pq), or
[SQLite](https://github.com/mattn/go-sqlite3) then you can avoid creating
DatastoreSegments by hand by using an integration package:

* [_integrations/nrpq](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrpq)
* [_integrations/nrmysql](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrmysql)
* [_integrations/nrsqlite3](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrsqlite3)

### External Segments

External segments appear in the transaction "Breakdown table" and in the
"External services" page. Version 1.11.0 of the Go Agent adds support for
cross-application tracing (CAT), which will result in external segments also
appearing in the "Service maps" page and being linked in transaction traces when
both sides of the request have traces. Version 2.1.0 of the Go Agent adds
support for distributed tracing, which lets you see the path a request takes as
it travels through distributed APM apps.

* [More info on External Services page](https://docs.newrelic.com/docs/apm/applications-menu/monitoring/external-services-page)
* [More info on Cross-Application Tracing](https://docs.newrelic.com/docs/apm/transactions/cross-application-traces/introduction-cross-application-traces)
* [More info on Distributed Tracing](https://docs.newrelic.com/docs/apm/distributed-tracing/getting-started/introduction-distributed-tracing)

External segments are instrumented using `ExternalSegment`. There are three
ways to use this functionality:

1. Using `StartExternalSegment` to create an `ExternalSegment` before the
   request is sent, and then calling `ExternalSegment.End` when the external
   request is complete.

   For CAT support to operate, an `http.Request` must be provided to
   `StartExternalSegment`, and the `ExternalSegment.Response` field must be set
   before `ExternalSegment.End` is called or deferred.

   For example:

    ```go
    func external(txn newrelic.Transaction, req *http.Request) (*http.Response, error) {
      s := newrelic.StartExternalSegment(txn, req)
      response, err := http.DefaultClient.Do(req)
      s.Response = response
      s.End()
      return response, err
    }
    ```

    If the transaction is `nil` then `StartExternalSegment` will look for a
    transaction in the request's context using
    [FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext).

2. Using `NewRoundTripper` to get a
   [`http.RoundTripper`](https://golang.org/pkg/net/http/#RoundTripper) that
   will automatically instrument all requests made via
   [`http.Client`](https://golang.org/pkg/net/http/#Client) instances that use
   that round tripper as their `Transport`. This option results in CAT support,
   provided the Go Agent is version 1.11.0, and in distributed tracing support,
   provided the Go Agent is version 2.1.0.  `NewRoundTripper` can be called
   with a `nil` or non-`nil` transaction:  If the transaction is `nil`, the
   round tripper will look for a transaction in the request's context
   using [FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext).
   This pattern is **strongly** recommended, since it allows the round tripper
   to be used in a client shared between multiple transactions.

   For example:

    ```go
    client := &http.Client{}
    client.Transport = newrelic.NewRoundTripper(nil, client.Transport)
    request, _ := http.NewRequest("GET", "http://example.com", nil)
    request = newrelic.RequestWithTransactionContext(request, txn)
    resp, err := client.Do(request)
    ```

   If transaction is non-`nil`, the round tripper returned **must** only be
   used in the same goroutine as the transaction.

3. Directly creating an `ExternalSegment` via a struct literal with an explicit
   `URL` or `Request`, and then calling `ExternalSegment.End`. This option does
   not support CAT, and may be removed or changed in a future major version of
   the Go Agent. As a result, we suggest using one of the other options above
   wherever possible.

   For example:

    ```go
    func external(txn newrelic.Transaction, url string) (*http.Response, error) {
      es := newrelic.ExternalSegment{
        StartTime: newrelic.StartSegmentNow(txn),
        URL:   url,
      }
      defer es.End()

      return http.Get(url)
    }
    ```

## Attributes

Attributes add context to errors and allow you to filter performance data
in Insights.

You may add them using the `Transaction.AddAttribute` method.

```go
txn.AddAttribute("key", "value")
txn.AddAttribute("product", "widget")
txn.AddAttribute("price", 19.99)
txn.AddAttribute("importantCustomer", true)
```

* [More info on Custom Attributes](https://docs.newrelic.com/docs/insights/new-relic-insights/decorating-events/insights-custom-attributes)

Some attributes are recorded automatically.  These are called agent attributes.
They are listed here:

* [attributes.go](attributes.go)

To disable one of these agents attributes, `AttributeResponseCode` for
example, modify the config like this:

```go
config.Attributes.Exclude = append(config.Attributes.Exclude, newrelic.AttributeResponseCode)
```

* [More info on Agent Attributes](https://docs.newrelic.com/docs/agents/manage-apm-agents/agent-metrics/agent-attributes)

## Tracing

New Relic's [distributed
tracing](https://docs.newrelic.com/docs/apm/distributed-tracing/getting-started/introduction-distributed-tracing)  
is the next generation of the previous cross-application tracing feature. Compared to
cross-application tracing, distributed tracing gives more detail about cross-service activity and provides more
complete end-to-end visibility.  This section discusses distributed tracing and cross-application tracing in turn.

### Distributed Tracing

New Relic's [distributed
tracing](https://docs.newrelic.com/docs/apm/distributed-tracing/getting-started/introduction-distributed-tracing)
feature lets you see the path that a request takes as it travels through distributed APM
apps, which is vital for applications implementing a service-oriented or
microservices architecture. Support for distributed tracing was added in
version 2.1.0 of the Go Agent.

The config's `DistributedTracer.Enabled` field has to be set. When true, the
agent will add distributed tracing headers in outbound requests, and scan
incoming requests for distributed tracing headers. Distributed tracing will
override cross-application tracing.

```go
config.DistributedTracer.Enabled = true
```

### Cross-Application Tracing

New Relic's
[cross-application tracing](https://docs.newrelic.com/docs/apm/transactions/cross-application-traces/introduction-cross-application-traces)
feature, or CAT for short, links transactions between applications in APM to
help identify performance problems within your service-oriented architecture.
Support for CAT was added in version 1.11.0 of the Go Agent.

As CAT uses HTTP headers to track requests across applications, the Go Agent
needs to be able to access and modify request and response headers both for
incoming and outgoing requests.

### Tracing Instrumentation

Both distributed tracing and cross-application tracing work by propagating
[header information](https://docs.newrelic.com/docs/apm/distributed-tracing/getting-started/how-new-relic-distributed-tracing-works#headers)
from service to service in a request path. In many scenarios, the Go Agent offers tracing instrumentation
out-of-the-box, for both distributed tracing and cross-application tracing. For other scenarios customers may implement
distributed tracing based on the examples provided in this guide.

#### Getting Tracing Instrumentation Out-of-the-Box

The Go Agent automatically creates and propagates tracing header information
for each of the following scenarios:

1. Using `WrapHandle` or `WrapHandleFunc` to instrument a server that
   uses [`http.ServeMux`](https://golang.org/pkg/net/http/#ServeMux)
   ([Example](examples/server/main.go)).

2. Using either of the Go Agent's [Gin](_integrations/nrgin/v1) or
   [Gorilla](_integrations/nrgorilla/v1) integration
   ([Gin Example](_integrations/nrgin/v1/example/main.go), [Gorilla Example](_integrations/nrgorilla/v1/example/main.go)).
.

3. Using another framework or [`http.Server`](https://golang.org/pkg/net/http/#Server) while ensuring that:

      1. All calls to `StartTransaction` include the response writer and
         request, and
      2. `Transaction.WriteHeader` is used instead of calling `WriteHeader`
         directly on the response writer, as described in the
         [transactions section of this guide](#transactions)
         ([Example](examples/server-http/main.go)).

4. Using `NewRoundTripper`, as described in the
   [external segments section of this guide](#external-segments)
   ([Example](examples/client-round-tripper/main.go)).

5. Using the call `StartExternalSegment` and providing an `http.Request`, as
   described in the [external segments section of this guide](#external-segments)
   ([Example](examples/client/main.go)).

#### Manually Implementing Distributed Tracing

Consider [manual instrumentation](https://docs.newrelic.com/docs/apm/distributed-tracing/enable-configure/enable-distributed-tracing#agent-apis)
for services not instrumented automatically by the Go Agent. In such scenarios, the
calling service has to generate a distributed trace payload:

```go
p := callingTxn.CreateDistributedTracePayload()
```

This payload has to be added to the call to the destination service, which in turn
invokes the call for accepting the payload:

```go
calledTxn.AcceptDistributedTracePayload(newrelic.TransportOther, p)
```

A complete example can be found
[here](examples/custom-instrumentation/main.go).


## Custom Metrics

* [More info on Custom Metrics](https://docs.newrelic.com/docs/agents/go-agent/instrumentation/create-custom-metrics-go)

You may [create custom metrics](https://docs.newrelic.com/docs/agents/manage-apm-agents/agent-data/collect-custom-metrics)
via the `RecordCustomMetric` method.

```go
app.RecordCustomMetric(
	"CustomMetricName", // Name of your metric
	132,                // Value
)
```

**Note:** The Go Agent will automatically prepend the metric name you pass to
`RecordCustomMetric` (`"CustomMetricName"` above) with the string `Custom/`.
This means the above code would produce a metric named
`Custom/CustomMetricName`.  You'll also want to read over the
[Naming Transactions and Metrics](#naming-transactions-and-metrics) section below for
advice on coming up with appropriate metric names.

## Custom Events

You may track arbitrary events using custom Insights events.

```go
app.RecordCustomEvent("MyEventType", map[string]interface{}{
	"myString": "hello",
	"myFloat":  0.603,
	"myInt":    123,
	"myBool":   true,
})
```

## Request Queuing

If you are running a load balancer or reverse web proxy then you may configure
it to add a `X-Queue-Start` header with a Unix timestamp.  This will create a
band on the application overview chart showing queue time.

* [More info on Request Queuing](https://docs.newrelic.com/docs/apm/applications-menu/features/request-queuing-tracking-front-end-time)

## Error Reporting

The Go Agent captures errors in three different ways:

1. [the Transaction.NoticeError method](#noticeerror)
2. [panics recovered in defer Transaction.End](#panics)
3. [error response status codes recorded with Transaction.WriteHeader](#error-response-codes)

### NoticeError

You may track errors using the `Transaction.NoticeError` method.  The easiest
way to get started with `NoticeError` is to use errors based on
[Go's standard error interface](https://blog.golang.org/error-handling-and-go).

```go
txn.NoticeError(errors.New("my error message"))
```

`NoticeError` will work with *any* sort of object that implements Go's standard
error type interface -- not just `errorStrings` created via `errors.New`.  

If you're interested in sending more than an error *message* to New Relic, the
Go Agent also offers a `newrelic.Error` struct.

```go
txn.NoticeError(newrelic.Error{
	Message: "my error message",
	Class:   "IdentifierForError",
	Attributes: map[string]interface{}{
		"important_number": 97232,
		"relevant_string":  "zap",
	},
})
```

Using the `newrelic.Error` struct requires you to manually marshal your error
data into the `Message`, `Class`, and `Attributes` fields.  However, there's two
**advantages** to using the `newrelic.Error` struct.

First, by setting an error `Class`, New Relic will be able to aggregate errors
in the *Error Analytics* section of APM.  Second, the `Attributes` field allows
you to send through key/value pairs with additional error debugging information
(also exposed in the *Error Analytics* section of APM).

### Advanced NoticeError Use

You're not limited to using Go's built-in error type or the provided
`newrelic.Error` struct.  The Go Agent provides three error interfaces

```go
type StackTracer interface {
	StackTrace() []uintptr
}

type ErrorClasser interface {
	ErrorClass() string
}

type ErrorAttributer interface {
	ErrorAttributes() map[string]interface{}
}
```

If you implement any of these on your own error structs, the `txn.NoticeError`
method will recognize these methods and use their return values to provide error
information.

For example, you could implement a custom error struct named `MyErrorWithClass`

```go
type MyErrorWithClass struct {

}
```

Then, you could implement both an `Error` method (per Go's standard `error`
interface) and an `ErrorClass` method (per the Go Agent `ErrorClasser`
interface) for this struct.

```go
func (e MyErrorWithClass) Error() string { return "A hard coded error message" }

// ErrorClass implements the ErrorClasser interface.
func (e MyErrorWithClass) ErrorClass() string { return "MyErrorClassForAggregation" }
```

Finally, you'd use your new error by creating a new instance of your struct and
passing it to the `NoticeError` method

```go
txn.NoticeError(MyErrorWithClass{})
```

While this is an oversimplified example, these interfaces give you a great deal
of control over what error information is available for your application.

### Panics

When the Transaction is ended using `defer`, the Transaction will recover any
panic that occurs, record it as an error, and re-throw it.  As a result, panics
may appear to be originating from `Transaction.End`.

```go
func unstableTask(app newrelic.Application) {
	txn := app.StartTransaction("unstableTask", nil, nil)
	defer txn.End()

	// This panic will be recorded as an error.
	panic("something went wrong")
}
```

### Error Response Codes

Since the
[Transaction](https://godoc.org/github.com/newrelic/go-agent#Transaction)
implements
[http.ResponseWriter](https://golang.org/pkg/net/http/#ResponseWriter), you can
use `Transaction.WriteHeader` to record the response status code.  The
transaction will record an error if the status code is above 400 or below 100
and not in the ignored status codes configuration list.  The ignored status
codes list is configured by the `Config.ErrorCollector.IgnoreStatusCodes` field
or within the New Relic UI if your application has server side configuration
enabled.

As a result, using `Transaction.NoticeError` in situations where your code is
returning an erroneous status code may result in redundant errors.
`NoticeError` is not affected by the ignored status codes configuration list.

## Naming Transactions and Metrics

You'll want to think carefully about how you name your transactions and custom
metrics.  If your program creates too many unique names, you may end up with a
[Metric Grouping Issue (or MGI)](https://docs.newrelic.com/docs/agents/manage-apm-agents/troubleshooting/metric-grouping-issues).

MGIs occur when the granularity of names is too fine, resulting in hundreds or
thousands of uniquely identified metrics and transactions.  One common cause of
MGIs is relying on the full URL name for metric naming in web transactions.  A
few major code paths may generate many different full URL paths to unique
documents, articles, page, etc. If the unique element of the URL path is
included in the metric name, each of these common paths will have its own unique
metric name.

## Browser

To enable support for
[New Relic Browser](https://docs.newrelic.com/docs/browser), your HTML pages
must include a JavaScript snippet that will load the Browser agent and
configure it with the correct application name. This snippet is available via
the `Transaction.BrowserTimingHeader` method.  Include the byte slice returned
by `Transaction.BrowserTimingHeader().WithTags()` as early as possible in the
`<head>` section of your HTML after any `<meta charset>` tags.

```go
func indexHandler(w http.ResponseWriter, req *http.Request) {
    io.WriteString(w, "<html><head>")
    // The New Relic browser javascript should be placed as high in the
    // HTML as possible.  We suggest including it immediately after the
    // opening <head> tag and any <meta charset> tags.
    if txn := FromContext(req.Context()); nil != txn {
        hdr, err := txn.BrowserTimingHeader()
        if nil != err {
            log.Printf("unable to create browser timing header: %v", err)
        }
        // BrowserTimingHeader() will always return a header whose methods can
        // be safely called.
        if js := hdr.WithTags(); js != nil {
            w.Write(js)
        }
    }
    io.WriteString(w, "</head><body>browser header page</body></html>")
}
```


## For More Help

There's a variety of places online to learn more about the Go Agent.

[The New Relic docs site](https://docs.newrelic.com/docs/agents/go-agent/get-started/introduction-new-relic-go)
contains a number of useful code samples and more context about how to use the Go Agent.

[New Relic's discussion forums](https://discuss.newrelic.com) have a dedicated
public forum [for the Go Agent](https://discuss.newrelic.com/c/support-products-agents/go-agent).

When in doubt, [the New Relic support site](https://support.newrelic.com/) is
the best place to get started troubleshooting an agent issue.
