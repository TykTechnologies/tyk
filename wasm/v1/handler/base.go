package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.Base = (*Base)(nil)

type Base struct {
	RootContext int32
}

func (b *Base) SetEffectiveContextID(contextID int32) x.WasmResult {
	return x.WasmResultOk
}

func (b *Base) GetRootContextID() int32 { return b.RootContext }

func (b *Base) ContextFinalize() x.WasmResult {
	return x.WasmResultOk
}

func (b *Base) SetTickPeriodMilliseconds(tickPeriodMilliseconds int32) x.WasmResult {
	return x.WasmResultOk
}
func (b *Base) GetCurrentTimeNanoseconds() (int32, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (b *Base) Done() x.WasmResult {
	return x.WasmResultUnimplemented
}
func (b *Base) Wait() x.Action {
	return x.ActionContinue
}
