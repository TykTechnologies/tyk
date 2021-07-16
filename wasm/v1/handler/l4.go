package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.L4 = (*L4)(nil)

type L4 struct{}

func (L4) GetDownStreamData() common.IoBuffer { return nil }
func (L4) GetUpstreamData() common.IoBuffer   { return nil }
func (L4) ResumeDownstream() x.WasmResult     { return x.WasmResultUnimplemented }
func (L4) ResumeUpstream() x.WasmResult       { return x.WasmResultUnimplemented }
