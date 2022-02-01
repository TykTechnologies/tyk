# jsonschema
[![Qri](https://img.shields.io/badge/made%20by-qri-magenta.svg?style=flat-square)](https://qri.io)
[![GoDoc](https://godoc.org/github.com/qri-io/jsonschema?status.svg)](http://godoc.org/github.com/qri-io/jsonschema)
[![License](https://img.shields.io/github/license/qri-io/jsonschema.svg?style=flat-square)](./LICENSE)
[![Codecov](https://img.shields.io/codecov/c/github/qri-io/jsonschema.svg?style=flat-square)](https://codecov.io/gh/qri-io/jsonschema)
[![CI](https://img.shields.io/circleci/project/github/qri-io/jsonschema.svg?style=flat-square)](https://circleci.com/gh/qri-io/jsonschema)
[![Go Report Card](https://goreportcard.com/badge/github.com/qri-io/jsonschema)](https://goreportcard.com/report/github.com/qri-io/jsonschema)

golang implementation of the [JSON Schema Specification](http://json-schema.org/), which lets you write JSON that validates some other json. Rad.

### Package Features

* Encode schemas back to JSON
* Supply Your own Custom Validators
* Uses Standard Go idioms
* Fastest Go implementation of [JSON Schema validators](http://json-schema.org/implementations.html#validators) (draft2019_9 only, (old — draft 7) benchmarks are [here](https://github.com/TheWildBlue/validator-benchmarks) — thanks [@TheWildBlue](https://github.com/TheWildBlue)!)

### Getting Involved

We would love involvement from more people! If you notice any errors or would
like to submit changes, please see our
[Contributing Guidelines](./.github/CONTRIBUTING.md).

### Developing

We’ve set up a separate document for [developer guidelines](https://github.com/qri-io/jsonschema/blob/master/DEVELOPERS.md)!

## Basic Usage

Here’s a quick example pulled from the [godoc](https://godoc.org/github.com/qri-io/jsonschema):

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/qri-io/jsonschema"
)

func main() {
	ctx := context.Background()
	var schemaData = []byte(`{
    "$id": "https://qri.io/schema/",
    "$comment" : "sample comment",
    "title": "Person",
    "type": "object",
    "properties": {
        "firstName": {
            "type": "string"
        },
        "lastName": {
            "type": "string"
        },
        "age": {
            "description": "Age in years",
            "type": "integer",
            "minimum": 0
        },
        "friends": {
          "type" : "array",
          "items" : { "title" : "REFERENCE", "$ref" : "#" }
        }
    },
    "required": ["firstName", "lastName"]
  }`)

	rs := &jsonschema.Schema{}
	if err := json.Unmarshal(schemaData, rs); err != nil {
		panic("unmarshal schema: " + err.Error())
	}

	var valid = []byte(`{
    "firstName" : "George",
    "lastName" : "Michael"
    }`)
	errs, err := rs.ValidateBytes(ctx, valid)
	if err != nil {
		panic(err)
	}

	if len(errs) > 0 {
		fmt.Println(errs[0].Error())
	}

	var invalidPerson = []byte(`{
    "firstName" : "Prince"
    }`)

	errs, err = rs.ValidateBytes(ctx, invalidPerson)
	if err != nil {
		panic(err)
	}
	if len(errs) > 0 {
		fmt.Println(errs[0].Error())
	}

	var invalidFriend = []byte(`{
    "firstName" : "Jay",
    "lastName" : "Z",
    "friends" : [{
      "firstName" : "Nas"
      }]
    }`)
	errs, err = rs.ValidateBytes(ctx, invalidFriend)
	if err != nil {
		panic(err)
	}
	if len(errs) > 0 {
		fmt.Println(errs[0].Error())
	}
}

// Output:
// /: {"firstName":"Prince... "lastName" value is required
// /friends/0: {"firstName":"Nas"} "lastName" value is required
```

## Custom Keywords

The [godoc](https://godoc.org/github.com/qri-io/jsonschema) gives an example of how to supply your own validators to extend the standard keywords supported by the spec.

It involves three steps that should happen _before_ allocating any Schema instances that use the validator:
1. create a custom type that implements the `Keyword` interface
2. Load the appropriate draft keyword set (see `draft2019_09_keywords.go`)
3. call RegisterKeyword with the keyword you’d like to detect in JSON, and a `KeyMaker` function.


```go
package main

import (
    "context"
    "encoding/json"
    "fmt"

    jptr "github.com/qri-io/jsonpointer"
    "github.com/qri-io/jsonschema"
)

// your custom validator
type IsFoo bool

// newIsFoo is a jsonschama.KeyMaker
func newIsFoo() jsonschema.Keyword {
    return new(IsFoo)
}

// Validate implements jsonschema.Keyword
func (f *IsFoo) Validate(propPath string, data interface{}, errs *[]jsonschema.KeyError) {}

// Register implements jsonschema.Keyword
func (f *IsFoo) Register(uri string, registry *jsonschema.SchemaRegistry) {}

// Resolve implements jsonschema.Keyword
func (f *IsFoo) Resolve(pointer jptr.Pointer, uri string) *jsonschema.Schema {
    return nil
}

// ValidateKeyword implements jsonschema.Keyword
func (f *IsFoo) ValidateKeyword(ctx context.Context, currentState *jsonschema.ValidationState, data interface{}) {
    if str, ok := data.(string); ok {
        if str != "foo" {
            currentState.AddError(data, fmt.Sprintf("should be foo. plz make '%s' == foo. plz", str))
        }
    }
}

func main() {
    // register a custom validator by supplying a function
    // that creates new instances of your Validator.
    jsonschema.RegisterKeyword("foo", newIsFoo)

    // If you register a custom validator, you'll need to manually register
    // any other JSON Schema validators you need.
    jsonschema.LoadDraft2019_09()

    schBytes := []byte(`{ "foo": true }`)

    rs := new(jsonschema.Schema)
    if err := json.Unmarshal(schBytes, rs); err != nil {
        // Real programs handle errors.
        panic(err)
    }

    errs, err := rs.ValidateBytes(context.Background(), []byte(`"bar"`))
    if err != nil {
        panic(err)
    }
    fmt.Println(errs[0].Error())
    // Output: /: "bar" should be foo. plz make 'bar' == foo. plz
}
```

