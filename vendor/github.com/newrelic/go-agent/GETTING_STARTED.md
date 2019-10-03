# Getting Started

Follow these steps to instrument your application.  More information is
available in the [GUIDE.md](GUIDE.md).

## Step 0: Installation

The New Relic Go agent is a Go library with no dependencies.  Install it the same way
you would install any other Go library.  The simplest way is to run:

```
go get github.com/newrelic/go-agent
```

Then import the `github.com/newrelic/go-agent` package in your application.

## Step 1: Create an Application

In your `main` function, or an `init` block, create an
[Application](https://godoc.org/github.com/newrelic/go-agent#Application) using
a [Config](https://godoc.org/github.com/newrelic/go-agent#Config).
[Application](https://godoc.org/github.com/newrelic/go-agent#Application) is the
starting point for all instrumentation.

```go
func main() {
	// Create a Config:
	config := newrelic.NewConfig("Your Application Name", "__YOUR_NEW_RELIC_LICENSE_KEY__")
	// Modify the Config to add logging or alter agent behavior:
	config.Logger = NewLogger(os.Stdout)
	// Then create an Application:
	app, err := newrelic.NewApplication(config)
	// If an application could not be created then err will reveal why.
	if err != nil {
		fmt.Println("unable to create New Relic Application", err)
	}
	// Now use the app to instrument everything!
}
```

Now start your application, and within minutes it will appear in the New Relic
UI.  Your application in New Relic won't contain much data (until we complete 
the steps below!), but you will already be able to see a 
[Go runtime](https://docs.newrelic.com/docs/agents/go-agent/features/go-runtime-page-troubleshoot-performance-problems) 
page that shows goroutine counts, garbage collection, memory, and CPU usage.

## Step 2: Instrument Requests Using Transactions

[Transactions](https://godoc.org/github.com/newrelic/go-agent#Transaction) are
used to time inbound requests and background tasks.  Use them to see your
application's throughput and response time.  The instrumentation strategy
depends on the framework you're using:

#### Standard HTTP Library

If you are using the standard library `http` package, use
[WrapHandle](https://godoc.org/github.com/newrelic/go-agent#WrapHandle) and
[WrapHandleFunc](https://godoc.org/github.com/newrelic/go-agent#WrapHandleFunc).
As an example, the following code:

```go
http.HandleFunc("/users", usersHandler)
```
Can be instrumented like this:
```go
http.HandleFunc(newrelic.WrapHandleFunc(app, "/users", usersHandler))
```

[Full Example Application](./examples/server/main.go)

#### Popular Web Framework

If you are using a popular framework, then there may be an integration package
designed to instrument it.  [List of New Relic Go agent integration packages](./README.md#integrations).

#### Manual Transactions

If you aren't using the `http` standard library package or an
integration package supported framework, you can create transactions
directly using the application's `StartTransaction` method:

```go
func myHandler(rw http.ResponseWriter, req *http.Request) {
	// The response writer and request parameters are optional.  If your
	// request is not an *http.Request, try using Transaction.SetWebRequest
	// with a custom newrelic.WebRequest.  If the request parameter is nil
	// then the transaction is considered a background task.
	txn := app.StartTransaction("myHandler", rw, req)
	defer txn.End()
}
```

Be sure to use a limited set of unique names to ensure that transactions are
grouped usefully.  Don't use dynamic URLs!

[More information about transactions](GUIDE.md#transactions)

## Step 3: Instrument Segments

Segments show you where the time in your transactions is being spent.  There are
three types of segments:
[Segment](https://godoc.org/github.com/newrelic/go-agent#Segment),
[ExternalSegment](https://godoc.org/github.com/newrelic/go-agent#ExternalSegment),
and
[DatastoreSegment](https://godoc.org/github.com/newrelic/go-agent#DatastoreSegment).

Creating a segment requires access to the transaction.  You can pass the
transaction around your functions as an explicit transaction parameter or inside
a [context.Context](https://golang.org/pkg/context/#Context).  Functions
[FromContext](https://godoc.org/github.com/newrelic/go-agent#FromContext) and
[NewContext](https://godoc.org/github.com/newrelic/go-agent#NewContext) make it
easy to store and retrieve the transaction from a context.

You may not even need to add the transaction to the context:
[WrapHandle](https://godoc.org/github.com/newrelic/go-agent#WrapHandle) and
[WrapHandleFunc](https://godoc.org/github.com/newrelic/go-agent#WrapHandleFunc)
add the transaction to the request's context automatically.

```go
func instrumentMe(ctx context.Context) {
	txn := newrelic.FromContext(ctx)
	segment := newrelic.StartSegment(txn, "instrumentMe")
	time.Sleep(1 * time.Second)
	segment.End()
}

func myHandler(w http.ResponseWriter, r *http.Request) {
	instrumentMe(r.Context())
}

func main() {
	cfg := newrelic.NewConfig("My App", "__YOUR_NEW_RELIC_LICENSE_KEY__")
	app, _ := newrelic.NewApplication(cfg)
	http.HandleFunc(newrelic.WrapHandleFunc(app, "/handler", myHandler))
}
```

[More information about segments](GUIDE.md#segments)

## Extra Credit

Read our [GUIDE.md](GUIDE.md) and the
[godocs](https://godoc.org/github.com/newrelic/go-agent) to learn more about
what else you can do with the Go Agent.
