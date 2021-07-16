package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.KeyValue = (*KeyValue)(nil)

type KeyValue struct{}

func (KeyValue) GetProperty(key string) (string, x.WasmResult) {
	return "", x.WasmResultUnimplemented
}
func (KeyValue) SetProperty(key string, value string) x.WasmResult {
	return x.WasmResultUnimplemented
}
