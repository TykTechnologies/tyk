package imports

import (
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ x.ImportsHandler = Imports(nil)

type Imports interface {
	Logger
	Base
	Plugin
	L4
	HTTPRequest
	HTTPResponse
	HTTPCall
	KeyValue
	SharedData
	Queue
	Metrics
	GRPC
	FFI
	CustomExtension
}

type Logger interface {
	Log(logLevel x.LogLevel, msg string) x.WasmResult
}

type Base interface {
	// for golang host environment
	// Wait until async call return, eg. sync http call in golang
	Wait() x.Action
	GetRootContextID() int32
	SetEffectiveContextID(contextID int32) x.WasmResult
	SetTickPeriodMilliseconds(tickPeriodMilliseconds int32) x.WasmResult
	GetCurrentTimeNanoseconds() (int32, x.WasmResult)
	Done() x.WasmResult
}

type Plugin interface {
	GetPluginConfig() common.IoBuffer
	GetVmConfig() common.IoBuffer
}

type KeyValue interface {
	GetProperty(key string) (string, x.WasmResult)
	SetProperty(key string, value string) x.WasmResult
}

type L4 interface {
	GetDownStreamData() common.IoBuffer
	GetUpstreamData() common.IoBuffer
	ResumeDownstream() x.WasmResult
	ResumeUpstream() x.WasmResult
}

type HTTPRequest interface {
	GetHttpRequestHeader() common.HeaderMap
	GetHttpRequestBody() common.IoBuffer
	GetHttpRequestTrailer() common.HeaderMap
	GetHttpRequestMetadata() common.HeaderMap
}

type HTTPResponse interface {
	GetHttpResponseHeader() common.HeaderMap
	GetHttpResponseBody() common.IoBuffer
	GetHttpResponseTrailer() common.HeaderMap
	GetHttpResponseMetadata() common.HeaderMap
	SendHttpResp(respCode int32, respCodeDetail common.IoBuffer, respBody common.IoBuffer, additionalHeaderMap common.HeaderMap, grpcCode int32) x.WasmResult
}

type HTTPCall interface {
	HttpCall(url string, headers common.HeaderMap, body common.IoBuffer, trailer common.HeaderMap, timeoutMilliseconds int32) (int32, x.WasmResult)
	GetHttpCallResponseHeaders() common.HeaderMap
	GetHttpCallResponseBody() common.IoBuffer
	GetHttpCallResponseTrailer() common.HeaderMap
	ResumeHttpRequest() x.WasmResult
	ResumeHttpResponse() x.WasmResult
}

type SharedData interface {
	GetSharedData(key string) (string, uint32, x.WasmResult)
	SetSharedData(key string, value string, cas uint32) x.WasmResult
}

type Queue interface {
	RegisterSharedQueue(queueName string) (uint32, x.WasmResult)
	RemoveSharedQueue(queueID uint32) x.WasmResult
	ResolveSharedQueue(queueName string) (uint32, x.WasmResult)
	EnqueueSharedQueue(queueID uint32, data string) x.WasmResult
	DequeueSharedQueue(queueID uint32) (string, x.WasmResult)
}

type Metrics interface {
	DefineMetric(metricType x.MetricType, name string) (int32, x.WasmResult)
	IncrementMetric(metricID int32, offset int64) x.WasmResult
	RecordMetric(metricID int32, value int64) x.WasmResult
	GetMetric(metricID int32) (int64, x.WasmResult)
	RemoveMetric(metricID int32) x.WasmResult
}

type GRPC interface {
	OpenGrpcStream(grpcService string, serviceName string, method string) (int32, x.WasmResult)
	SendGrpcCallMsg(token int32, data common.IoBuffer, endOfStream int32) x.WasmResult
	CancelGrpcCall(token int32) x.WasmResult
	CloseGrpcCall(token int32) x.WasmResult

	GrpcCall(grpcService string, serviceName string, method string, data common.IoBuffer, timeoutMilliseconds int32) (int32, x.WasmResult)
	GetGrpcReceiveInitialMetaData() common.HeaderMap
	GetGrpcReceiveBuffer() common.IoBuffer
	GetGrpcReceiveTrailerMetaData() common.HeaderMap
}

type FFI interface {
	CallForeignFunction(funcName string, param []byte) ([]byte, x.WasmResult)
	GetFuncCallData() common.IoBuffer
}

type CustomExtension interface {
	GetCustomBuffer(bufferType x.BufferType) common.IoBuffer
	GetCustomHeader(mapType x.MapType) common.HeaderMap
}
