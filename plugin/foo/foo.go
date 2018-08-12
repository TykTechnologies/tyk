package main

import (
	"net/http"
)

type Foo struct{}

// Do sets `Foo: Bar` on a request header
func (f Foo) Do(r *http.Request) error {
	r.Header.Set("Foo", "Bar")

	return nil
}

var Fooer Foo
