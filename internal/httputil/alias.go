package httputil

import (
	"net/http/httputil"
)

var (
	DumpRequest  = httputil.DumpRequest
	DumpResponse = httputil.DumpResponse
)
