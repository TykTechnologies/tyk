package handler

import (
	"encoding/json"

	"github.com/TykTechnologies/tyk/wasm"
	"github.com/TykTechnologies/tyk/wasm/buffers"
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"github.com/golang/protobuf/jsonpb"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
)

var _ imports.Plugin = (*Plugin)(nil)
var m jsonpb.Marshaler

type Plugin struct {
	Instance  wasm.InstanceConfig
	Config    map[string]interface{}
	NewBuffer func() *buffers.IO
}

func safeBuffer() (create func() *buffers.IO, release func()) {
	var ls []*buffers.IO
	return func() *buffers.IO {
			b := buffers.Get()
			ls = append(ls, b)
			return b
		}, func() {
			buffers.Put(ls...)
		}
}

func (p *Plugin) GetPluginConfig() common.IoBuffer {
	if p.Config == nil {
		return nil
	}
	if p.NewBuffer == nil {
		return nil
	}
	if p.Config != nil {
		buf := p.NewBuffer()
		json.NewEncoder(buf).Encode(p.Config)
		return buf
	}
	return nil
}

func (p *Plugin) GetVmConfig() common.IoBuffer {
	if p.Config == nil {
		return nil
	}
	if p.NewBuffer == nil {
		return nil
	}
	buf := p.NewBuffer()
	json.NewEncoder(buf).Encode(p.Instance)
	return buf
}
