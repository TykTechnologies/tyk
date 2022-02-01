[![Qri](https://img.shields.io/badge/made%20by-qri-magenta.svg?style=flat-square)](https://qri.io)
[![GoDoc](https://godoc.org/github.com/qri-io/jsonpointer?status.svg)](http://godoc.org/github.com/qri-io/jsonpointer)
[![License](https://img.shields.io/github/license/qri-io/jsonpointer.svg?style=flat-square)](./LICENSE)
[![Codecov](https://img.shields.io/codecov/c/github/qri-io/jsonpointer.svg?style=flat-square)](https://codecov.io/gh/qri-io/jsonpointer)
[![CI](https://img.shields.io/circleci/project/github/qri-io/jsonpointer.svg?style=flat-square)](https://circleci.com/gh/qri-io/jsonpointer)
[![Go Report Card](https://goreportcard.com/badge/github.com/qri-io/jsonpointer)](https://goreportcard.com/report/github.com/qri-io/jsonpointer)


# jsonpointer
golang implementation of [IETF RFC6901](https://tools.ietf.org/html/rfc6901):
_JSON Pointer defines a string syntax for identifying a specific value within a JavaScript Object Notation (JSON) document._

### Installation
install with:
`go get -u github.com/qri-io/jsonpointer`


### Usage
Here's a quick example pulled from the [godoc](https://godoc.org/github.com/qri-io/jsonpointer):

```go
import (
  "encoding/json"
  "fmt"
  "github.com/qri-io/jsonpointer"
)

var document = []byte(`{ 
  "foo": {
    "bar": {
      "baz": [0,"hello!"]
    }
  }
}`)

func main() {
  parsed := map[string]interface{}{}
  // be sure to handle errors in real-world code!
  json.Unmarshal(document, &parsed)

  // parse a json pointer. Pointers can also be url fragments
  // the following are equivelent pointers:
  // "/foo/bar/baz/1"
  // "#/foo/bar/baz/1"
  // "http://example.com/document.json#/foo/bar/baz/1"
  ptr, _ := jsonpointer.Parse("/foo/bar/baz/1")

  // evaluate the pointer against the document
  // evaluation always starts at the root of the document
  got, _ := ptr.Eval(parsed)

  fmt.Println(got)
  // Output: hello!
}

```

### License
MIT

### Issues & Contributions
Contributions & Issues are more than welcome! Everything happens over on this repo's [github page](https://github.com/qri-io/jsonpointer)