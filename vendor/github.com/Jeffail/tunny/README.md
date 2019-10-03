![Tunny](tunny_logo.png "Tunny")

Tunny is a Golang library for spawning and managing a goroutine pool.

The API is synchronous and simple to use. Jobs are allocated to a worker when one becomes available.

https://godoc.org/github.com/Jeffail/tunny

##How to install:

```bash
go get github.com/jeffail/tunny
```

##How to use:

The most obvious use for a goroutine pool would be limiting heavy jobs to the number of CPUs available. In the example below we limit the work from arbitrary numbers of HTTP request goroutines through our pool.

```go
package main

import (
	"io/ioutil"
	"net/http"
	"runtime"

	"github.com/jeffail/tunny"
)

func main() {
	numCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUs+1) // numCPUs hot threads + one for async tasks.

	pool, _ := tunny.CreatePool(numCPUs, func(object interface{}) interface{} {
		input, _ := object.([]byte)

		// Do something that takes a lot of work
		output := input

		return output
	}).Open()

	defer pool.Close()

	http.HandleFunc("/work", func(w http.ResponseWriter, r *http.Request) {
		input, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}

		// Send work to our pool
		result, _ := pool.SendWork(input)

		w.Write(result.([]byte))
	})

	http.ListenAndServe(":8080", nil)
}
```

Tunny supports timeouts. You can replace the `SendWork` call above to the following:

```go
		// Or, alternatively, send it with a timeout (in this case 5 seconds).
		result, err := pool.SendWorkTimed(5000, input)
		if err != nil {
			http.Error(w, "Request timed out", http.StatusRequestTimeout)
		}
```

##Can I send a closure instead of data?

Yes, the arguments passed to the worker are boxed as interface{}, so this can actually be a func, you can implement this yourself, or if you're not bothered about return values you can use:

```go
exampleChannel := make(chan int)

pool, _ := tunny.CreatePoolGeneric(numCPUs).Open()

err := pool.SendWork(func() {
	/* Do your hard work here, usual rules of closures apply here,
	 * so you can return values like so:
	 */
	exampleChannel <- 10
})

if err != nil {
	// You done goofed
}
```

##How do I give my workers state?

Tunny workers implement the `TunnyWorkers` interface, simply implement this interface to have your own objects (and state) act as your workers.

```go
/*
TunnyWorker - The basic interface of a tunny worker.
*/
type TunnyWorker interface {

	// Called for each job, expects the result to be returned synchronously
	TunnyJob(interface{}) interface{}

	// Called after each job, this indicates whether the worker is ready for the next job.
	// The default implementation is to return true always. If false is returned then the
	// method is called every five milliseconds until either true is returned or the pool
	// is closed.
	TunnyReady() bool
}
```

Here is a short example:

```go
type customWorker struct {
	// TODO: Put some state here
}

// Use this call to block further jobs if necessary
func (worker *customWorker) TunnyReady() bool {
	return true
}

// This is where the work actually happens
func (worker *customWorker) TunnyJob(data interface{}) interface{} {
	/* TODO: Use and modify state
	 * there's no need for thread safety paradigms here unless the
	 * data is being accessed from another goroutine outside of
	 * the pool.
	 */
	if outputStr, ok := data.(string); ok {
		return ("custom job done: " + outputStr)
	}
	return nil
}

func TestCustomWorkers (t *testing.T) {
	outChan := make(chan int, 10)

	wg := new(sync.WaitGroup)
	wg.Add(10)

	workers := make([]tunny.TunnyWorker, 4)
	for i, _ := range workers {
		workers[i] = &(customWorker{})
	}

	pool, _ := tunny.CreateCustomPool(workers).Open()

	defer pool.Close()

	for i := 0; i < 10; i++ {
		go func() {
			value, _ := pool.SendWork("hello world")
			fmt.Println(value.(string))

			wg.Done()
		}()
	}

	wg.Wait()
}
```

The TunnyReady method allows you to use your state to determine whether or not a worker should take on another job. For example, your worker could hold a counter of how many jobs it has done, and perhaps after a certain amount it should perform another act before taking on more work, it's important to use TunnyReady for these occasions since blocking the TunnyJob call will hold up the waiting client.

It is recommended that you do not block TunnyReady() whilst you wait for some condition to change, since this can prevent the pool from closing the worker goroutines. Currently, TunnyReady is called at 5 millisecond intervals until you answer true or the pool is closed.

##I need more control

You crazy fool, let's take this up to the next level. You can optionally implement `TunnyExtendedWorker` for more control.

```go
/*
TunnyExtendedWorker - An optional interface that can be implemented if the worker needs
more control over its state.
*/
type TunnyExtendedWorker interface {

	// Called when the pool is opened, this will be called before any jobs are sent.
	TunnyInitialize()

	// Called when the pool is closed, this will be called after all jobs are completed.
	TunnyTerminate()
}
```

##Can a worker detect when a timeout occurs?

Yes, you can also implement the `TunnyInterruptable` interface.

```go
/*
TunnyInterruptable - An optional interface that can be implemented in order to allow the
worker to drop jobs when they are abandoned.
*/
type TunnyInterruptable interface {

	// Called when the current job has been abandoned by the client.
	TunnyInterrupt()
}
```

This method will be called in the event that a timeout occurs whilst waiting for the result. `TunnyInterrupt` is called from a newly spawned goroutine, so you'll need to create your own mechanism for stopping your worker mid-way through a job.

##Can SendWork be called asynchronously?

There are the helper functions SendWorkAsync and SendWorkTimedAsync, that are the same as their respective sync calls with an optional second argument func(interface{}, error), this is the call made when a result is returned and can be nil if there is no need for the closure.

However, if you find yourself in a situation where the sync return is not necessary then chances are you don't actually need Tunny at all. Golang is all about making concurrent programming simple by nature, and using Tunny for implementing simple async worker calls defeats the great work of the language spec and adds overhead that isn't necessary.

##Behaviours and caveats:

###- Workers request jobs on an ad-hoc basis

When there is a backlog of jobs waiting to be serviced, and all workers are occupied, a job will not be assigned to a worker until it is already prepared for its next job. This means workers do not develop their own individual queues. Instead, the backlog is shared by the entire pool.

This means an individual worker is able to halt, or spend exceptional lengths of time on a single request without hindering the flow of any other requests, provided there are other active workers in the pool.

###- A job can be dropped before work is begun

Tunny has support for specified timeouts at the work request level, if this timeout is triggered whilst waiting for a worker to become available then the request is dropped entirely and no effort is wasted on the abandoned request.

###- Backlogged jobs are FIFO, for now

When a job arrives and all workers are occupied the waiting thread will lock at a select block whilst waiting to be assigned a worker. In practice this seems to create a FIFO queue, implying that this is how the implementation of Golang has dealt with select blocks, channels and multiple reading goroutines.

However, I haven't found a guarantee of this behaviour in the Golang documentation, so I cannot guarantee that this will always be the case.
