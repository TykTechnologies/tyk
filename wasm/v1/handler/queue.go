package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.Queue = (*Queue)(nil)

type Queue struct{}

func (Queue) RegisterSharedQueue(queueName string) (uint32, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (Queue) RemoveSharedQueue(queueID uint32) x.WasmResult { return x.WasmResultUnimplemented }
func (Queue) ResolveSharedQueue(queueName string) (uint32, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (Queue) EnqueueSharedQueue(queueID uint32, data string) x.WasmResult {
	return x.WasmResultUnimplemented
}
func (Queue) DequeueSharedQueue(queueID uint32) (string, x.WasmResult) {
	return "", x.WasmResultUnimplemented
}
