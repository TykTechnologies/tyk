package handler

import (
	"github.com/TykTechnologies/tyk/wasm/v1/imports"
	x "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var _ imports.Metrics = (*Metrics)(nil)

type Metrics struct{}

func (Metrics) DefineMetric(metricType x.MetricType, name string) (int32, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (Metrics) IncrementMetric(metricID int32, offset int64) x.WasmResult {
	return x.WasmResultUnimplemented
}
func (Metrics) RecordMetric(metricID int32, value int64) x.WasmResult {
	return x.WasmResultUnimplemented
}
func (Metrics) GetMetric(metricID int32) (int64, x.WasmResult) {
	return 0, x.WasmResultUnimplemented
}
func (Metrics) RemoveMetric(metricID int32) x.WasmResult { return x.WasmResultUnimplemented }
