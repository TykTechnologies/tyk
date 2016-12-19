## leakybucket

Leaky bucket implementation in Go with your choice of data storage layer.

## Why

[Leaky buckets](https://en.wikipedia.org/wiki/Leaky_bucket) are useful in a number of settings, especially rate limiting.

## Documentation

[![GoDoc](https://godoc.org/github.com/Clever/leakybucket?status.png)](https://godoc.org/github.com/Clever/leakybucket).

## Tests

leakybucket is built and tested against Go 1.5.
Ensure this is the version of Go you're running with `go version`.
Make sure your GOPATH is set, e.g. `export GOPATH=~/go`.
Clone the repository to `$GOPATH/src/github.com/Clever/leakybucket`.

If you have done all of the above, then you should be able to run

```
make test
```
