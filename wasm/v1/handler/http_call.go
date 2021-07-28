package handler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/TykTechnologies/tyk/wasm/buffers"
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.HTTPCall = (*HTTPCall)(nil)

var httpCalloutID atomic.Int32

type HTTPCall struct {
	calloutID, contextID int32
	log                  *logrus.Entry
	response             *http.Response
	body                 *buffers.IO
	client               *http.Client
	newBuffer            func() *buffers.IO
	exports              x.Exports
}

func (h *HTTPCall) setupClient(timeout int32) {
	ts := time.Millisecond * time.Duration(timeout)
	if h.client == nil {
		h.client = &http.Client{
			Timeout: ts,
		}
	} else {
		h.client.Timeout = ts
	}
}

func (h *HTTPCall) HttpCall(reqURL string, headers common.HeaderMap, body common.IoBuffer, trailer common.HeaderMap, timeoutMilliseconds int32) (int32, x.WasmResult) {
	calloutID := httpCalloutID.Inc()
	log := h.log.WithFields(logrus.Fields{
		"url":       reqURL,
		"calloutID": calloutID,
	})

	method, _ := headers.Get(":method")
	path, _ := headers.Get(":path")

	headers.Del(":method")
	headers.Del(":path")

	u, err := url.Parse(fmt.Sprintf("%s%s", reqURL, path))
	if err != nil {
		log.WithError(err).Error("HttpCall fail to parse url")
		return 0, x.WasmResultBadArgument
	}

	h.setupClient(timeoutMilliseconds)

	req, err := http.NewRequest(
		method, u.String(),
		bytes.NewReader(body.Bytes()),
	)
	if err != nil {
		log.WithError(err).Error("failed to create new request")
		return 0, x.WasmResultInternalFailure
	}

	headers.Range(func(k string, v string) bool {
		req.Header.Set(k, v)
		return true
	})
	res, err := h.client.Do(req)
	if err != nil {
		log.WithError(err).Error("failed to make client call")
		return 0, x.WasmResultInternalFailure
	}
	defer res.Body.Close()
	h.response = res
	if h.body == nil {
		h.body = h.newBuffer()
	}
	h.body.Reset()
	io.Copy(h.body, res.Body)
	h.calloutID = calloutID
	return calloutID, x.WasmResultOk
}

func (h *HTTPCall) ProxyOnHttpCallResponse() error {
	if h.response != nil {
		return h.exports.ProxyOnHttpCallResponse(
			h.contextID, h.calloutID, int32(len(h.response.Header)), int32(h.body.Len()),
			int32(len(h.response.Trailer)),
		)
	}
	return nil
}

func (h *HTTPCall) GetHttpCallResponseHeaders() common.HeaderMap {
	if h.response != nil {
		return &Header{head: h.response.Header}
	}
	return nil
}

func (h *HTTPCall) GetHttpCallResponseBody() common.IoBuffer {
	if h.body != nil {
		return h.body
	}
	return nil
}

func (h *HTTPCall) GetHttpCallResponseTrailer() common.HeaderMap {
	if h.response != nil {
		return &Header{head: h.response.Trailer}
	}
	return nil
}
func (HTTPCall) ResumeHttpRequest() x.WasmResult  { return x.WasmResultUnimplemented }
func (HTTPCall) ResumeHttpResponse() x.WasmResult { return x.WasmResultUnimplemented }
