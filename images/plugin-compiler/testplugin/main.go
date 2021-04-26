package main

import (
	"net/http"
)

// AddFooBarHeader adds custom "Foo: Bar" header to the request
//nolint:deadcode
func AddFooBarHeader(rw http.ResponseWriter, r *http.Request) {
	r.Header.Add("Foo", "Bar")
}

func main() {}
