package gojsonschema

import (
	"github.com/xeipuuv/gojsonschema"
)

type (
	JSONLoader              = gojsonschema.JSONLoader
	ResultError             = gojsonschema.ResultError
	Result                  = gojsonschema.Result
	FormatCheckerChain      = gojsonschema.FormatCheckerChain
	DoesNotMatchFormatError = gojsonschema.DoesNotMatchFormatError
)

var (
	NewBytesLoader = gojsonschema.NewBytesLoader
	NewGoLoader    = gojsonschema.NewGoLoader
	FormatCheckers = gojsonschema.FormatCheckers
	Validate       = gojsonschema.Validate
)
