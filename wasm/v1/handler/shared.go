package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.SharedData = (*SharedData)(nil)

type SharedData struct{}

func (SharedData) GetSharedData(key string) (string, uint32, x.WasmResult) {
	return "", 0, x.WasmResultUnimplemented
}
func (SharedData) SetSharedData(key string, value string, cas uint32) x.WasmResult {
	return x.WasmResultUnimplemented
}
