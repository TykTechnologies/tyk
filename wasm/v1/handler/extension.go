package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.CustomExtension = (*CustomExtension)(nil)

type CustomExtension struct{}

func (CustomExtension) GetCustomBuffer(bufferType x.BufferType) common.IoBuffer {
	return nil
}
func (CustomExtension) GetCustomHeader(mapType x.MapType) common.HeaderMap {
	return nil
}
