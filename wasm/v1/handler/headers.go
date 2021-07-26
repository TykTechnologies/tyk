package handler

import (
	"bytes"
	"net/http"
	"sync"

	"mosn.io/proxy-wasm-go-host/proxywasm/common"
)

var _ common.HeaderMap = (*Header)(nil)

type Header struct {
	head http.Header
}

func (h *Header) Get(key string) (string, bool) {
	headerVal := h.head.Get(key)
	if headerVal == "" {
		return "", false
	}
	return headerVal, true
}

func (h *Header) Set(key, value string) {
	h.head.Set(key, value)
}

func (h *Header) Add(key, value string) {
	h.head.Add(key, value)
}

func (h *Header) Del(key string) {
	h.head.Del(key)
}

func (h *Header) Range(f func(key, value string) bool) {
	for k := range h.head {
		if !f(k, h.head.Get(k)) {
			return
		}
	}
}

func (h *Header) Clone() common.HeaderMap {
	return &Header{head: h.head.Clone()}
}

var byteBuf = &sync.Pool{
	New: func() interface{} { return new(bytes.Buffer) },
}

func (h *Header) ByteSize() uint64 {
	b := byteBuf.Get().(*bytes.Buffer)
	defer func() {
		b.Reset()
		byteBuf.Put(b)
	}()
	h.head.Write(b)
	return uint64(b.Len())
}
