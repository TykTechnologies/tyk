package gojsonschema

import (
	"github.com/xeipuuv/gojsonschema"
)

type (
	// SW-REQ-039
	JSONLoader              = gojsonschema.JSONLoader
	ResultError             = gojsonschema.ResultError
	Result                  = gojsonschema.Result
	FormatCheckerChain      = gojsonschema.FormatCheckerChain
	DoesNotMatchFormatError = gojsonschema.DoesNotMatchFormatError
)

var (
	// SW-REQ-039
	NewBytesLoader = gojsonschema.NewBytesLoader
	NewGoLoader    = gojsonschema.NewGoLoader
	FormatCheckers = gojsonschema.FormatCheckers
	Validate       = gojsonschema.Validate
)
