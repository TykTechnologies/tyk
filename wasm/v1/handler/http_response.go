package handler

import (
	"net/http"

	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
)

var _ imports.HTTPResponse = (*Response)(nil)

type Response struct {
	Response http.ResponseWriter
}

func (Response) GetHttpResponseHeader() common.HeaderMap   { return nil }
func (Response) GetHttpResponseBody() common.IoBuffer      { return nil }
func (Response) GetHttpResponseTrailer() common.HeaderMap  { return nil }
func (Response) GetHttpResponseMetadata() common.HeaderMap { return nil }
