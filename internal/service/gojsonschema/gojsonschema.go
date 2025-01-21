package gojsonschema

import (
	"github.com/xeipuuv/gojsonschema"
)

type JSONLoader = gojsonschema.JSONLoader
type ResultError = gojsonschema.ResultError

var NewBytesLoader = gojsonschema.NewBytesLoader
var NewGoLoader = gojsonschema.NewGoLoader
var Validate = gojsonschema.Validate
