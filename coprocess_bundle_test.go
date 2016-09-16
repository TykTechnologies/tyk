package main

import(
  "testing"
  "fmt"
)

func TestBundleGetter(t *testing.T) {
}

func TestHttpBundleGetter(t *testing.T) {
  var thisGetter BundleGetter
  thisGetter = &HttpBundleGetter{}

  thisGetter.Get()
  
  fmt.Println(thisGetter)
}
