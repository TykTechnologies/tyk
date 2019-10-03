## ChangeLog

## 2.13.0

### New Features

* Added support for [HttpRouter](https://github.com/julienschmidt/httprouter) in
  the new [_integrations/nrhttprouter](http://godoc.org/github.com/newrelic/go-agent/_integrations/nrhttprouter) package.  This package allows you to easily instrument inbound requests through the HttpRouter framework.

  * [Documentation](http://godoc.org/github.com/newrelic/go-agent/_integrations/nrhttprouter)
  * [Example](_integrations/nrhttprouter/example/main.go)

* Added support for [github.com/uber-go/zap](https://github.com/uber-go/zap) in
  the new
  [_integrations/nrzap](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrzap)
  package.  This package allows you to send agent log messages to `zap`.

## 2.12.0

### New Features

* Added new methods to expose `Transaction` details:

  * `Transaction.GetTraceMetadata()` returns a
    [TraceMetadata](https://godoc.org/github.com/newrelic/go-agent#TraceMetadata)
    which contains distributed tracing identifiers.

  * `Transaction.GetLinkingMetadata()` returns a
    [LinkingMetadata](https://godoc.org/github.com/newrelic/go-agent#LinkingMetadata)
    which contains the fields needed to link data to a trace or entity.

* Added a new plugin for the [Logrus logging
  framework](https://github.com/sirupsen/logrus) with the new
  [_integrations/logcontext/nrlogrusplugin](https://github.com/newrelic/go-agent/go-agent/tree/master/_integrations/logcontext/nrlogrusplugin)
  package. This plugin leverages the new `GetTraceMetadata` and
  `GetLinkingMetadata` above to decorate logs.

  To enable, set your log's formatter to the `nrlogrusplugin.ContextFormatter{}`

  ```go
  logger := logrus.New()
  logger.SetFormatter(nrlogrusplugin.ContextFormatter{})
  ```

  The logger will now look for a `newrelic.Transaction` inside its context and
  decorate logs accordingly.  Therefore, the Transaction must be added to the
  context and passed to the logger.  For example, this logging call

  ```go
  logger.Info("Hello New Relic!")
  ```

  must be transformed to include the context, such as:

  ```go
  ctx := newrelic.NewContext(context.Background(), txn)
  logger.WithContext(ctx).Info("Hello New Relic!")
  ```

  For full documentation see the
  [godocs](https://godoc.org/github.com/newrelic/go-agent/_integrations/logcontext/nrlogrusplugin)
  or view the
  [example](https://github.com/newrelic/go-agent/blob/master/_integrations/logcontext/nrlogrusplugin/example/main.go).

* Added support for [NATS](https://github.com/nats-io/nats.go) and [NATS Streaming](https://github.com/nats-io/stan.go)
monitoring with the new [_integrations/nrnats](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrnats) and
[_integrations/nrstan](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrstan) packages.  These packages
support instrumentation of publishers and subscribers.

  * [NATS Example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrnats/examples/main.go)
  * [NATS Streaming Example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrstan/examples/main.go)

* Enables ability to migrate to [Configurable Security Policies (CSP)](https://docs.newrelic.com/docs/agents/manage-apm-agents/configuration/enable-configurable-security-policies) on a per agent basis for accounts already using [High Security Mode (HSM)](https://docs.newrelic.com/docs/agents/manage-apm-agents/configuration/high-security-mode).
  * Previously, if CSP was configured for an account, New Relic would not allow an agent to connect without the `security_policies_token`. This led to agents not being able to connect during the period between when CSP was enabled for an account and when each agent is configured with the correct token.
  * With this change, when both HSM and CSP are enabled for an account, an agent (this version or later) can successfully connect with either `high_security: true` or the appropriate `security_policies_token` configured - allowing the agent to continue to connect after CSP is configured on the account but before the appropriate `security_policies_token` is configured for each agent.

## 2.11.0

### New Features

* Added support for [Micro](https://github.com/micro/go-micro) monitoring with the new
[_integrations/nrmicro](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrmicro)
package.  This package supports instrumentation for servers, clients, publishers, and subscribers.

  * [Server Example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrmicro/example/server/server.go)
  * [Client Example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrmicro/example/client/client.go)
  * [Publisher and Subscriber Example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrmicro/example/pubsub/main.go)
  * [Full godocs Documentation](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrmicro)

* Added support for creating static `WebRequest` instances manually via the `NewStaticWebRequest` function. This can be useful when you want to create a web transaction but don't have an `http.Request` object. Here's an example of creating a static `WebRequest` and using it to mark a transaction as a web transaction:
  ```go
  hdrs := http.Headers{}
  u, _ := url.Parse("http://example.com")
  webReq := newrelic.NewStaticWebRequest(hdrs, u, "GET", newrelic.TransportHTTP)
  txn := app.StartTransaction("My-Transaction", nil, nil)
  txn.SetWebRequest(webReq)
  ```

## 2.10.0

### New Features

* Added support for custom events when using
  [nrlambda](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlambda).
  Example Lambda handler which creates custom event:

   ```go
   func handler(ctx context.Context) {
		if txn := newrelic.FromContext(ctx); nil != txn {
			txn.Application().RecordCustomEvent("myEvent", map[string]interface{}{
				"zip": "zap",
			})
		}
		fmt.Println("hello world!")
   }
   ```

## 2.9.0

### New Features

* Added support for [gRPC](https://github.com/grpc/grpc-go) monitoring with the new
[_integrations/nrgrpc](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgrpc)
package.  This package supports instrumentation for servers and clients.

  * [Server Example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrgrpc/example/server/server.go)
  * [Client Example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrgrpc/example/client/client.go)

* Added new
  [ExternalSegment](https://godoc.org/github.com/newrelic/go-agent#ExternalSegment)
  fields `Host`, `Procedure`, and `Library`.  These optional fields are
  automatically populated from the segment's `URL` or `Request` if unset.  Use
  them if you don't have access to a request or URL but still want useful external
  metrics, transaction segment attributes, and span attributes.
  * `Host` is used for external metrics, transaction trace segment names, and
    span event names.  The host of segment's `Request` or `URL` is the default.
  * `Procedure` is used for transaction breakdown metrics.  If set, it should be
    set to the remote procedure being called.  The HTTP method of the segment's `Request` is the default.
  * `Library` is used for external metrics and the `"component"` span attribute.
    If set, it should be set to the framework making the call. `"http"` is the default.

  With the addition of these new fields, external transaction breakdown metrics
  are changed: `External/myhost.com/all` will now report as
  `External/myhost.com/http/GET` (provided the HTTP method is `GET`).

* HTTP Response codes below `100`, except `0` and `5`, are now recorded as
  errors.  This is to support `gRPC` status codes.  If you start seeing
  new status code errors that you would like to ignore, add them to
  `Config.ErrorCollector.IgnoreStatusCodes` or your server side configuration
  settings.

* Improve [logrus](https://github.com/sirupsen/logrus) support by introducing
  [nrlogrus.Transform](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlogrus#Transform),
  a function which allows you to turn a
  [logrus.Logger](https://godoc.org/github.com/sirupsen/logrus#Logger) instance into a
  [newrelic.Logger](https://godoc.org/github.com/newrelic/go-agent#Logger).
  Example use:

  ```go
  l := logrus.New()
  l.SetLevel(logrus.DebugLevel)
  cfg := newrelic.NewConfig("Your Application Name", "__YOUR_NEW_RELIC_LICENSE_KEY__")
  cfg.Logger = nrlogrus.Transform(l)
  ```

  As a result of this change, the
  [nrlogrus](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlogrus)
  package requires [logrus](https://github.com/sirupsen/logrus) version `v1.1.0`
  and above.

## 2.8.1

### Bug Fixes

* Removed `nrmysql.NewConnector` since
  [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql) has not yet
  released `mysql.NewConnector`.

## 2.8.0

### New Features

* Introduce support for databases using
  [database/sql](https://golang.org/pkg/database/sql/).  This new functionality
  allows you to instrument MySQL, PostgreSQL, and SQLite calls without manually
  creating
  [DatastoreSegment](https://godoc.org/github.com/newrelic/go-agent#DatastoreSegment)s.

  | Database Library Supported | Integration Package |
  | ------------- | ------------- |
  | [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql) | [_integrations/nrmysql](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrmysql) |
  | [lib/pq](https://github.com/lib/pq) | [_integrations/nrpq](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrpq) |
  | [mattn/go-sqlite3](https://github.com/mattn/go-sqlite3) | [_integrations/nrsqlite3](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrsqlite3) |

  Using these database integration packages is easy!  First replace the driver
  with our integration version:

  ```go
  import (
  	// import our integration package in place of "github.com/go-sql-driver/mysql"
  	_ "github.com/newrelic/go-agent/_integrations/nrmysql"
  )

  func main() {
  	// open "nrmysql" in place of "mysql"
  	db, err := sql.Open("nrmysql", "user@unix(/path/to/socket)/dbname")
  }
  ```

  Second, use the `ExecContext`, `QueryContext`, and `QueryRowContext` methods of
  [sql.DB](https://golang.org/pkg/database/sql/#DB),
  [sql.Conn](https://golang.org/pkg/database/sql/#Conn),
  [sql.Tx](https://golang.org/pkg/database/sql/#Tx), and
  [sql.Stmt](https://golang.org/pkg/database/sql/#Stmt) and provide a
  transaction-containing context.  Calls to `Exec`, `Query`, and `QueryRow` do not
  get instrumented.

  ```go
  ctx := newrelic.NewContext(context.Background(), txn)
  row := db.QueryRowContext(ctx, "SELECT count(*) from tables")
  ```

  If you are using a [database/sql](https://golang.org/pkg/database/sql/) database
  not listed above, you can write your own instrumentation for it using
  [InstrumentSQLConnector](https://godoc.org/github.com/newrelic/go-agent#InstrumentSQLConnector),
  [InstrumentSQLDriver](https://godoc.org/github.com/newrelic/go-agent#InstrumentSQLDriver),
  and
  [SQLDriverSegmentBuilder](https://godoc.org/github.com/newrelic/go-agent#SQLDriverSegmentBuilder).
  The integration packages act as examples of how to do this.

  For more information, see the [Go agent documentation on instrumenting datastore segments](https://docs.newrelic.com/docs/agents/go-agent/instrumentation/instrument-go-segments#go-datastore-segments).

### Bug Fixes

* The [http.RoundTripper](https://golang.org/pkg/net/http/#RoundTripper) returned
  by [NewRoundTripper](https://godoc.org/github.com/newrelic/go-agent#NewRoundTripper)
  no longer modifies the request.  Our thanks to @jlordiales for the contribution.

## 2.7.0

### New Features

* Added support for server side configuration.  Server side configuration allows
 you to set the following configuration settings in the New Relic APM UI:

  * `Config.TransactionTracer.Enabled`
  * `Config.ErrorCollector.Enabled`
  * `Config.CrossApplicationTracer.Enabled`
  * `Config.TransactionTracer.Threshold`
  * `Config.TransactionTracer.StackTraceThreshold`
  * `Config.ErrorCollector.IgnoreStatusCodes`

  For more information see the [server side configuration documentation](https://docs.newrelic.com/docs/agents/manage-apm-agents/configuration/server-side-agent-configuration).

* Added support for AWS Lambda functions in the new
  [nrlambda](_integrations/nrlambda)
  package.  Please email <lambda_preview@newrelic.com> if you are interested in
  learning more or previewing New Relic Lambda monitoring.  This instrumentation
  package requires `aws-lambda-go` version
  [v1.9.0](https://github.com/aws/aws-lambda-go/releases) and above.

  * [documentation](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrlambda)
  * [working example](_integrations/nrlambda/example/main.go)

## 2.6.0

### New Features

* Added support for async: the ability to instrument multiple concurrent
  goroutines, or goroutines that access or manipulate the same Transaction.

  The new `Transaction.NewGoroutine() Transaction` method allows
  transactions to create segments in multiple goroutines!

  `NewGoroutine` returns a new reference to the `Transaction`.  This must be
  called any time you are passing the `Transaction` to another goroutine which
  makes segments.  Each segment-creating goroutine must have its own `Transaction`
  reference.  It does not matter if you call this before or after the other
  goroutine has started.

  All `Transaction` methods can be used in any `Transaction` reference.  The
  `Transaction` will end when `End()` is called in any goroutine.

  Example passing a new `Transaction` reference directly to another goroutine:

  ```go
  	go func(txn newrelic.Transaction) {
  		defer newrelic.StartSegment(txn, "async").End()
  		time.Sleep(100 * time.Millisecond)
  	}(txn.NewGoroutine())
  ```

  Example passing a new `Transaction` reference on a channel to another
  goroutine:

  ```go
  	ch := make(chan newrelic.Transaction)
  	go func() {
  		txn := <-ch
  		defer newrelic.StartSegment(txn, "async").End()
  		time.Sleep(100 * time.Millisecond)
  	}()
  	ch <- txn.NewGoroutine()
  ```

* Added integration support for
  [`aws-sdk-go`](https://github.com/aws/aws-sdk-go) and
  [`aws-sdk-go-v2`](https://github.com/aws/aws-sdk-go-v2).

  When using these SDKs, a segment will be created for each out going request.
  For DynamoDB calls, these will be Datastore segments and for all others they
  will be External segments.
  * [v1 Documentation](http://godoc.org/github.com/newrelic/go-agent/_integrations/nrawssdk/v1)
  * [v2 Documentation](http://godoc.org/github.com/newrelic/go-agent/_integrations/nrawssdk/v2)

* Added span event and transaction trace segment attribute configuration.  You
  may control which attributes are captured in span events and transaction trace
  segments using the `Config.SpanEvents.Attributes` and
  `Config.TransactionTracer.Segments.Attributes` settings. For example, if you
  want to disable the collection of `"db.statement"` in your span events, modify
  your config like this:

  ```go
  cfg.SpanEvents.Attributes.Exclude = append(cfg.SpanEvents.Attributes.Exclude,
  	newrelic.SpanAttributeDBStatement)
  ```

  To disable the collection of all attributes from your transaction trace
  segments, modify your config like this:

  ```go
  cfg.TransactionTracer.Segments.Attributes.Enabled = false
  ```

### Bug Fixes

* Fixed a bug that would prevent External Segments from being created under
  certain error conditions related to Cross Application Tracing.

### Miscellaneous

* Improved linking between Cross Application Transaction Traces in the APM UI.
  When `Config.CrossApplicationTracer.Enabled = true`, External segments in the
  Transaction Traces details will now link to the downstream Transaction Trace
  if there is one. Additionally, the segment name will now include the name of
  the downstream application and the name of the downstream transaction.

* Update attribute names of Datastore and External segments on Transaction
  Traces to be in line with attribute names on Spans. Specifically:
    * `"uri"` => `"http.url"`
    * `"query"` => `"db.statement"`
    * `"database_name"` => `"db.instance"`
    * `"host"` => `"peer.hostname"`
    * `"port_path_or_id"` + `"host"` => `"peer.address"`

## 2.5.0

* Added support for [New Relic Browser](https://docs.newrelic.com/docs/browser)
  using the new `BrowserTimingHeader` method on the
  [`Transaction`](https://godoc.org/github.com/newrelic/go-agent#Transaction)
  which returns a
  [BrowserTimingHeader](https://godoc.org/github.com/newrelic/go-agent#BrowserTimingHeader).
  The New Relic Browser JavaScript code measures page load timing, also known as
  real user monitoring.  The Pro version of this feature measures AJAX requests,
  single-page applications, JavaScript errors, and much more!  Example use:

```go
func browser(w http.ResponseWriter, r *http.Request) {
	hdr, err := w.(newrelic.Transaction).BrowserTimingHeader()
	if nil != err {
		log.Printf("unable to create browser timing header: %v", err)
	}
	// BrowserTimingHeader() will always return a header whose methods can
	// be safely called.
	if js := hdr.WithTags(); js != nil {
		w.Write(js)
	}
	io.WriteString(w, "browser header page")
}
```

* The Go agent now collects an attribute named `request.uri` on Transaction
  Traces, Transaction Events, Error Traces, and Error Events.  `request.uri`
  will never contain user, password, query parameters, or fragment.  To prevent
  the request's URL from being collected in any data, modify your `Config` like
  this:

```go
cfg.Attributes.Exclude = append(cfg.Attributes.Exclude, newrelic.AttributeRequestURI)
```

## 2.4.0

* Introduced `Transaction.Application` method which returns the `Application`
  that started the `Transaction`.  This method is useful since it may prevent
  having to pass the `Application` to code that already has access to the
  `Transaction`.  Example use:

```go
txn.Application().RecordCustomEvent("customerOrder", map[string]interface{}{
	"numItems":   2,
	"totalPrice": 13.75,
})
```

* The `Transaction.AddAttribute` method no longer accepts `nil` values since
  our backend ignores them.

## 2.3.0

* Added support for [Echo](https://echo.labstack.com) in the new `nrecho`
  package.
  * [Documentation](http://godoc.org/github.com/newrelic/go-agent/_integrations/nrecho)
  * [Example](_integrations/nrecho/example/main.go)

* Introduced `Transaction.SetWebResponse(http.ResponseWriter)` method which sets
  the transaction's response writer.  After calling this method, the
  `Transaction` may be used in place of the `http.ResponseWriter` to intercept
  the response code.  This method is useful when the `http.ResponseWriter` is
  not available at the beginning of the transaction (if so, it can be given as a
  parameter to `Application.StartTransaction`).  This method will return a
  reference to the transaction which implements the combination of
  `http.CloseNotifier`, `http.Flusher`, `http.Hijacker`, and `io.ReaderFrom`
  implemented by the ResponseWriter.  Example:

```go
func setResponseDemo(txn newrelic.Transaction) {
	recorder := httptest.NewRecorder()
	txn = txn.SetWebResponse(recorder)
	txn.WriteHeader(200)
	fmt.Println("response code recorded:", recorder.Code)
}
```

* The `Transaction`'s `http.ResponseWriter` methods may now be called safely if
  a `http.ResponseWriter` has not been set.  This allows you to add a response code
  to the transaction without using a `http.ResponseWriter`.  Example:

```go
func transactionWithResponseCode(app newrelic.Application) {
       txn := app.StartTransaction("hasResponseCode", nil, nil)
       defer txn.End()
       txn.WriteHeader(200) // Safe!
}
```

* The agent now collects environment variables prefixed by
  `NEW_RELIC_METADATA_`.  Some of these may be added
  Transaction events to provide context between your Kubernetes cluster and your
  services. For details on the benefits (currently in beta) see [this blog
  post](https://blog.newrelic.com/engineering/monitoring-application-performance-in-kubernetes/)

* The agent now collects the `KUBERNETES_SERVICE_HOST` environment variable to
  detect when the application is running on Kubernetes.

* The agent now collects the fully qualified domain name of the host and
  local IP addresses for improved linking with our infrastructure product.

## 2.2.0

* The `Transaction` parameter to
[NewRoundTripper](https://godoc.org/github.com/newrelic/go-agent#NewRoundTripper)
and
[StartExternalSegment](https://godoc.org/github.com/newrelic/go-agent#StartExternalSegment)
is now optional:  If it is `nil`, then a `Transaction` will be looked for in the
request's context (using
[FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext)).
Passing a `nil` transaction is **STRONGLY** recommended when using
[NewRoundTripper](https://godoc.org/github.com/newrelic/go-agent#NewRoundTripper)
since it allows one `http.Client.Transport` to be used for multiple
transactions.  Example use:

```go
client := &http.Client{}
client.Transport = newrelic.NewRoundTripper(nil, client.Transport)
request, _ := http.NewRequest("GET", "http://example.com", nil)
request = newrelic.RequestWithTransactionContext(request, txn)
resp, err := client.Do(request)
```

* Introduced `Transaction.SetWebRequest(WebRequest)` method which marks the
transaction as a web transaction.  If the `WebRequest` parameter is non-nil,
`SetWebRequest` will collect details on request attributes, url, and method.
This method is useful if you don't have access to the request at the beginning
of the transaction, or if your request is not an `*http.Request` (just add
methods to your request that satisfy
[WebRequest](https://godoc.org/github.com/newrelic/go-agent#WebRequest)).  To
use an `*http.Request` as the parameter, use the
[NewWebRequest](https://godoc.org/github.com/newrelic/go-agent#NewWebRequest)
transformation function.  Example:

```go
var request *http.Request = getInboundRequest()
txn.SetWebRequest(newrelic.NewWebRequest(request))
```

* Fixed `Debug` in `nrlogrus` package.  Previous versions of the New Relic Go Agent incorrectly
logged to Info level instead of Debug.  This has now been fixed.  Thanks to @paddycarey for catching this.

* [nrgin.Transaction](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgin/v1#Transaction)
may now be called with either a `context.Context` or a `*gin.Context`.  If you were passing a `*gin.Context`
around your functions as a `context.Context`, you may access the Transaction by calling either
[nrgin.Transaction](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgin/v1#Transaction)
or [FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext).
These functions now work nicely together.
For example, [FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext) will return the `Transaction`
added by [nrgin.Middleware](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgin/v1#Middleware).
Thanks to @rodriguezgustavo for the suggestion.  

## 2.1.0

* The Go Agent now supports distributed tracing.

  Distributed tracing lets you see the path that a request takes as it travels through your distributed system. By
  showing the distributed activity through a unified view, you can troubleshoot and understand a complex system better
  than ever before.

  Distributed tracing is available with an APM Pro or equivalent subscription. To see a complete distributed trace, you
  need to enable the feature on a set of neighboring services. Enabling distributed tracing changes the behavior of
  some New Relic features, so carefully consult the
  [transition guide](https://docs.newrelic.com/docs/transition-guide-distributed-tracing) before you enable this
  feature.

  To enable distributed tracing, set the following fields in your config.  Note that distributed tracing and cross
  application tracing cannot be used simultaneously.

```
  config := newrelic.NewConfig("Your Application Name", "__YOUR_NEW_RELIC_LICENSE_KEY__")
  config.CrossApplicationTracer.Enabled = false
  config.DistributedTracer.Enabled = true
```

  Please refer to the
  [distributed tracing section of the guide](GUIDE.md#distributed-tracing)
  for more detail on how to ensure you get the most out of the Go agent's distributed tracing support.

* Added functions [NewContext](https://godoc.org/github.com/newrelic/go-agent#NewContext)
  and [FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext)
  for adding and retrieving the Transaction from a Context.  Handlers
  instrumented by
  [WrapHandle](https://godoc.org/github.com/newrelic/go-agent#WrapHandle),
  [WrapHandleFunc](https://godoc.org/github.com/newrelic/go-agent#WrapHandleFunc),
  and [nrgorilla.InstrumentRoutes](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrgorilla/v1#InstrumentRoutes)
  may use [FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext)
  on the request's context to access the Transaction.
  Thanks to @caarlos0 for the contribution!  Though [NewContext](https://godoc.org/github.com/newrelic/go-agent#NewContext)
  and [FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext)
  require Go 1.7+ (when [context](https://golang.org/pkg/context/) was added),
  [RequestWithTransactionContext](https://godoc.org/github.com/newrelic/go-agent#RequestWithTransactionContext) is always exported so that it can be used in all framework and library
  instrumentation.

## 2.0.0

* The `End()` functions defined on the `Segment`, `DatastoreSegment`, and
  `ExternalSegment` types now receive the segment as a pointer, rather than as
  a value. This prevents unexpected behaviour when a call to `End()` is
  deferred before one or more fields are changed on the segment.

  In practice, this is likely to only affect this pattern:

    ```go
    defer newrelic.DatastoreSegment{
      // ...
    }.End()
    ```

  Instead, you will now need to separate the literal from the deferred call:

    ```go
    ds := newrelic.DatastoreSegment{
      // ...
    }
    defer ds.End()
    ```

  When creating custom and external segments, we recommend using
  [`newrelic.StartSegment()`](https://godoc.org/github.com/newrelic/go-agent#StartSegment)
  and
  [`newrelic.StartExternalSegment()`](https://godoc.org/github.com/newrelic/go-agent#StartExternalSegment),
  respectively.

* Added GoDoc badge to README.  Thanks to @mrhwick for the contribution!

* `Config.UseTLS` configuration setting has been removed to increase security.
   TLS will now always be used in communication with New Relic Servers.

## 1.11.0

* We've closed the Issues tab on GitHub. Please visit our
  [support site](https://support.newrelic.com) to get timely help with any
  problems you're having, or to report issues.

* Added support for Cross Application Tracing (CAT). Please refer to the
  [CAT section of the guide](GUIDE.md#cross-application-tracing)
  for more detail on how to ensure you get the most out of the Go agent's new
  CAT support.

* The agent now collects additional metadata when running within Amazon Web
  Services, Google Cloud Platform, Microsoft Azure, and Pivotal Cloud Foundry.
  This information is used to provide an enhanced experience when the agent is
  deployed on those platforms.

## 1.10.0

* Added new `RecordCustomMetric` method to [Application](https://godoc.org/github.com/newrelic/go-agent#Application).
  This functionality can be used to track averages or counters without using
  custom events.
  * [Custom Metric Documentation](https://docs.newrelic.com/docs/agents/manage-apm-agents/agent-data/collect-custom-metrics)

* Fixed import needed for logrus.  The import Sirupsen/logrus had been renamed to sirupsen/logrus.
  Thanks to @alfred-landrum for spotting this.

* Added [ErrorAttributer](https://godoc.org/github.com/newrelic/go-agent#ErrorAttributer),
  an optional interface that can be implemented by errors provided to
  `Transaction.NoticeError` to attach additional attributes.  These attributes are
  subject to attribute configuration.

* Added [Error](https://godoc.org/github.com/newrelic/go-agent#Error), a type
  that allows direct control of error fields.  Example use:

```go
txn.NoticeError(newrelic.Error{
	// Message is returned by the Error() method.
	Message: "error message: something went very wrong",
	Class:   "errors are aggregated by class",
	Attributes: map[string]interface{}{
		"important_number": 97232,
		"relevant_string":  "zap",
	},
})
```

* Updated license to address scope of usage.

## 1.9.0

* Added support for [github.com/gin-gonic/gin](https://github.com/gin-gonic/gin)
  in the new `nrgin` package.
  * [Documentation](http://godoc.org/github.com/newrelic/go-agent/_integrations/nrgin/v1)
  * [Example](examples/_gin/main.go)

## 1.8.0

* Fixed incorrect metric rule application when the metric rule is flagged to
  terminate and matches but the name is unchanged.

* `Segment.End()`, `DatastoreSegment.End()`, and `ExternalSegment.End()` methods now return an
  error which may be helpful in diagnosing situations where segment data is unexpectedly missing.

## 1.7.0

* Added support for [gorilla/mux](http://github.com/gorilla/mux) in the new `nrgorilla`
  package.
  * [Documentation](http://godoc.org/github.com/newrelic/go-agent/_integrations/nrgorilla/v1)
  * [Example](examples/_gorilla/main.go)

## 1.6.0

* Added support for custom error messages and stack traces.  Errors provided
  to `Transaction.NoticeError` will now be checked to see if
  they implement [ErrorClasser](https://godoc.org/github.com/newrelic/go-agent#ErrorClasser)
  and/or [StackTracer](https://godoc.org/github.com/newrelic/go-agent#StackTracer).
  Thanks to @fgrosse for this proposal.

* Added support for [pkg/errors](https://github.com/pkg/errors).  Thanks to
  @fgrosse for this work.
  * [documentation](https://godoc.org/github.com/newrelic/go-agent/_integrations/nrpkgerrors)
  * [example](https://github.com/newrelic/go-agent/blob/master/_integrations/nrpkgerrors/nrpkgerrors.go)

* Fixed tests for Go 1.8.

## 1.5.0

* Added support for Windows.  Thanks to @ianomad and @lvxv for the contributions.

* The number of heap objects allocated is recorded in the
  `Memory/Heap/AllocatedObjects` metric.  This will soon be displayed on the "Go
  runtime" page.

* If the [DatastoreSegment](https://godoc.org/github.com/newrelic/go-agent#DatastoreSegment)
  fields `Host` and `PortPathOrID` are not provided, they will no longer appear
  as `"unknown"` in transaction traces and slow query traces.

* Stack traces will now be nicely aligned in the APM UI.

## 1.4.0

* Added support for slow query traces.  Slow datastore segments will now
 generate slow query traces viewable on the datastore tab.  These traces include
 a stack trace and help you to debug slow datastore activity.
 [Slow Query Documentation](https://docs.newrelic.com/docs/apm/applications-menu/monitoring/viewing-slow-query-details)

* Added new
[DatastoreSegment](https://godoc.org/github.com/newrelic/go-agent#DatastoreSegment)
fields `ParameterizedQuery`, `QueryParameters`, `Host`, `PortPathOrID`, and
`DatabaseName`.  These fields will be shown in transaction traces and in slow
query traces.

## 1.3.0

* Breaking Change: Added a timeout parameter to the `Application.Shutdown` method.

## 1.2.0

* Added support for instrumenting short-lived processes:
  * The new `Application.Shutdown` method allows applications to report
    data to New Relic without waiting a full minute.
  * The new `Application.WaitForConnection` method allows your process to
    defer instrumentation until the application is connected and ready to
    gather data.
  * Full documentation here: [application.go](application.go)
  * Example short-lived process: [examples/short-lived-process/main.go](examples/short-lived-process/main.go)

* Error metrics are no longer created when `ErrorCollector.Enabled = false`.

* Added support for [github.com/mgutz/logxi](github.com/mgutz/logxi).  See
  [_integrations/nrlogxi/v1/nrlogxi.go](_integrations/nrlogxi/v1/nrlogxi.go).

* Fixed bug where Transaction Trace thresholds based upon Apdex were not being
  applied to background transactions.

## 1.1.0

* Added support for Transaction Traces.

* Stack trace filenames have been shortened: Any thing preceding the first
  `/src/` is now removed.

## 1.0.0

* Removed `BetaToken` from the `Config` structure.

* Breaking Datastore Change:  `datastore` package contents moved to top level
  `newrelic` package.  `datastore.MySQL` has become `newrelic.DatastoreMySQL`.

* Breaking Attributes Change:  `attributes` package contents moved to top
  level `newrelic` package.  `attributes.ResponseCode` has become
  `newrelic.AttributeResponseCode`.  Some attribute name constants have been
  shortened.

* Added "runtime.NumCPU" to the environment tab.  Thanks sergeylanzman for the
  contribution.

* Prefixed the environment tab values "Compiler", "GOARCH", "GOOS", and
  "Version" with "runtime.".

## 0.8.0

* Breaking Segments API Changes:  The segments API has been rewritten with the
  goal of being easier to use and to avoid nil Transaction checks.  See:

  * [segments.go](segments.go)
  * [examples/server/main.go](examples/server/main.go)
  * [GUIDE.md#segments](GUIDE.md#segments)

* Updated LICENSE.txt with contribution information.

## 0.7.1

* Fixed a bug causing the `Config` to fail to serialize into JSON when the
  `Transport` field was populated.

## 0.7.0

* Eliminated `api`, `version`, and `log` packages.  `Version`, `Config`,
  `Application`, and `Transaction` now live in the top level `newrelic` package.
  If you imported the  `attributes` or `datastore` packages then you will need
  to remove `api` from the import path.

* Breaking Logging Changes

Logging is no longer controlled though a single global.  Instead, logging is
configured on a per-application basis with the new `Config.Logger` field.  The
logger is an interface described in [log.go](log.go).  See
[GUIDE.md#logging](GUIDE.md#logging).

## 0.6.1

* No longer create "GC/System/Pauses" metric if no GC pauses happened.

## 0.6.0

* Introduced beta token to support our beta program.

* Rename `Config.Development` to `Config.Enabled` (and change boolean
  direction).

* Fixed a bug where exclusive time could be incorrect if segments were not
  ended.

* Fix unit tests broken in 1.6.

* In `Config.Enabled = false` mode, the license must be the proper length or empty.

* Added runtime statistics for CPU/memory usage, garbage collection, and number
  of goroutines.

## 0.5.0

* Added segment timing methods to `Transaction`.  These methods must only be
  used in a single goroutine.

* The license length check will not be performed in `Development` mode.

* Rename `SetLogFile` to `SetFile` to reduce redundancy.

* Added `DebugEnabled` logging guard to reduce overhead.

* `Transaction` now implements an `Ignore` method which will prevent
  any of the transaction's data from being recorded.

* `Transaction` now implements a subset of the interfaces
  `http.CloseNotifier`, `http.Flusher`, `http.Hijacker`, and `io.ReaderFrom`
  to match the behavior of its wrapped `http.ResponseWriter`.

* Changed project name from `go-sdk` to `go-agent`.

## 0.4.0

* Queue time support added: if the inbound request contains an
`"X-Request-Start"` or `"X-Queue-Start"` header with a unix timestamp, the
agent will report queue time metrics.  Queue time will appear on the
application overview chart.  The timestamp may fractional seconds,
milliseconds, or microseconds: the agent will deduce the correct units.
