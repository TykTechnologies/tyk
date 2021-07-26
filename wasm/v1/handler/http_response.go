package handler

import (
	"net/http"

	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.HTTPResponse = (*Response)(nil)

type Response struct {
	Response   http.ResponseWriter
	statusCode *int
	err        error
}

func (r *Response) GetStatusDetail() error { return r.err }

func (r *Response) GetStatus() int {
	if r.statusCode != nil {
		// Magic number to stop further execution of the middleware chain. If this set
		// then status code and response have already been written as well
		return 666
	}
	return http.StatusOK
}

func (Response) GetHttpResponseHeader() common.HeaderMap   { return nil }
func (Response) GetHttpResponseBody() common.IoBuffer      { return nil }
func (Response) GetHttpResponseTrailer() common.HeaderMap  { return nil }
func (Response) GetHttpResponseMetadata() common.HeaderMap { return nil }

func (res *Response) SendHttpResp(respCode int32, respCodeDetail common.IoBuffer, respBody common.IoBuffer, additionalHeaderMap common.HeaderMap, grpcCode int32) x.WasmResult {
	additionalHeaderMap.Range(func(key, value string) bool {
		res.Response.Header().Set(key, value)
		return true
	})
	code := int(respCode)
	res.statusCode = &code
	res.Response.WriteHeader(code)
	if respBody.Len() > 0 {
		res.Response.Write(respBody.Bytes())
	}
	return x.WasmResultOk
}
