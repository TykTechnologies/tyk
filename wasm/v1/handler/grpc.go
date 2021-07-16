package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.GRPC = (*GRPC)(nil)

type GRPC struct{}

func (GRPC) OpenGrpcStream(grpcService string, serviceName string, method string) (int32, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (GRPC) SendGrpcCallMsg(token int32, data common.IoBuffer, endOfStream int32) x.WasmResult {
	return x.WasmResultUnimplemented
}
func (GRPC) CancelGrpcCall(token int32) x.WasmResult { return x.WasmResultUnimplemented }
func (GRPC) CloseGrpcCall(token int32) x.WasmResult  { return x.WasmResultUnimplemented }

func (GRPC) GrpcCall(grpcService string, serviceName string, method string, data common.IoBuffer, timeoutMilliseconds int32) (int32, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (GRPC) GetGrpcReceiveInitialMetaData() common.HeaderMap { return nil }
func (GRPC) GetGrpcReceiveBuffer() common.IoBuffer           { return nil }
func (GRPC) GetGrpcReceiveTrailerMetaData() common.HeaderMap { return nil }
