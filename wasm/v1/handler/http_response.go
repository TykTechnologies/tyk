package handler

import (
	"net/http"

	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.HTTPResponse = (*Response)(nil)

type Response struct {
	Response http.ResponseWriter
}

func (Response) GetHttpResponseHeader() common.HeaderMap   { return nil }
func (Response) GetHttpResponseBody() common.IoBuffer      { return nil }
func (Response) GetHttpResponseTrailer() common.HeaderMap  { return nil }
func (Response) GetHttpResponseMetadata() common.HeaderMap { return nil }

func (res Response) SendHttpResp(respCode int32, respCodeDetail common.IoBuffer, respBody common.IoBuffer, additionalHeaderMap common.HeaderMap, grpcCode int32) x.WasmResult {
	additionalHeaderMap.Range(func(key, value string) bool {
		res.Response.Header().Set(key, value)
		return true
	})
	if respBody.Len() > 0 {
		res.Response.Write(respBody.Bytes())
	}
	res.Response.WriteHeader(int(respCode))
	return x.WasmResultOk
}
