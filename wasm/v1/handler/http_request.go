package handler

import (
	"net/http"

	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
)

var _ imports.HTTPRequest = (*Request)(nil)

type Request struct {
	Request *http.Request
}

func (r *Request) GetHttpRequestHeader() common.HeaderMap {
	if r.Request == nil {
		return nil
	}
	return &Header{head: r.Request.Header}
}

func (r *Request) GetHttpRequestBody() common.IoBuffer {
	if r.Request == nil {
		return nil
	}
	if io, ok := r.Request.Body.(common.IoBuffer); ok {
		return io
	}
	return nil
}

func (r *Request) GetHttpRequestTrailer() common.HeaderMap {
	if r.Request == nil {
		return nil
	}
	return &Header{head: r.Request.Trailer}
}

func (r *Request) GetHttpRequestMetadata() common.HeaderMap {
	if r.Request == nil {
		return nil
	}
	return &Header{head: r.Request.Trailer}
}
