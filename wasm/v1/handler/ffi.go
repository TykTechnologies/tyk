package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.FFI = (*FFI)(nil)

type FFI struct{}

func (FFI) CallForeignFunction(funcName string, param []byte) ([]byte, x.WasmResult) {
	return nil, x.WasmResultUnimplemented
}
func (FFI) GetFuncCallData() common.IoBuffer { return nil }
