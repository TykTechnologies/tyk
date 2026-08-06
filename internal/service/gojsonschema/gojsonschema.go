package gojsonschema

import (
	"github.com/xeipuuv/gojsonschema"
)

type (
	JSONLoader                = gojsonschema.JSONLoader
	ResultError               = gojsonschema.ResultError
	Result                    = gojsonschema.Result
	FormatCheckerChain        = gojsonschema.FormatCheckerChain
	DoesNotMatchFormatError   = gojsonschema.DoesNotMatchFormatError
	FormatChecker             = gojsonschema.FormatChecker
	URIFormatChecker          = gojsonschema.URIFormatChecker
	URIReferenceFormatChecker = gojsonschema.URIReferenceFormatChecker
)

var (
	NewBytesLoader = gojsonschema.NewBytesLoader
	NewGoLoader    = gojsonschema.NewGoLoader
	FormatCheckers = gojsonschema.FormatCheckers
	Validate       = gojsonschema.Validate
)
