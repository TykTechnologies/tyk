package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.HTTPCall = (*HTTPCall)(nil)

type HTTPCall struct{}

func (HTTPCall) HttpCall(url string, headers common.HeaderMap, body common.IoBuffer, trailer common.HeaderMap, timeoutMilliseconds int32) (int32, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (HTTPCall) GetHttpCallResponseHeaders() common.HeaderMap { return nil }
func (HTTPCall) GetHttpCallResponseBody() common.IoBuffer     { return nil }
func (HTTPCall) GetHttpCallResponseTrailer() common.HeaderMap { return nil }
func (HTTPCall) ResumeHttpRequest() x.WasmResult              { return x.WasmResultUnimplemented }
func (HTTPCall) ResumeHttpResponse() x.WasmResult             { return x.WasmResultUnimplemented }
