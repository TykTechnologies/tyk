// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metric

import "go.opentelemetry.io/otel/api/kv"

// Int64ObserverCallback is a type of callback that integral
// observers run.
type Int64ObserverCallback func(Int64ObserverResult)

// Float64ObserverCallback is a type of callback that floating point
// observers run.
type Float64ObserverCallback func(Float64ObserverResult)

// BatchObserverCallback is a callback argument for use with any
// Observer instrument that will be reported as a batch of
// observations.
type BatchObserverCallback func(BatchObserverResult)

// Int64Observer is a metric that captures a set of int64 values at a
// point in time.
type Int64Observer struct {
	asyncInstrument
}

// Float64Observer is a metric that captures a set of float64 values
// at a point in time.
type Float64Observer struct {
	asyncInstrument
}

// BatchObserver represents an Observer callback that can report
// observations for multiple instruments.
type BatchObserver struct {
	meter  Meter
	runner AsyncBatchRunner
}

// Int64ObserverResult is passed to an observer callback to capture
// observations for one asynchronous integer metric instrument.
type Int64ObserverResult struct {
	instrument AsyncImpl
	function   func([]kv.KeyValue, ...Observation)
}

// Float64ObserverResult is passed to an observer callback to capture
// observations for one asynchronous floating point metric instrument.
type Float64ObserverResult struct {
	instrument AsyncImpl
	function   func([]kv.KeyValue, ...Observation)
}

// BatchObserverResult is passed to a batch observer callback to
// capture observations for multiple asynchronous instruments.
type BatchObserverResult struct {
	function func([]kv.KeyValue, ...Observation)
}

// AsyncRunner is expected to convert into an AsyncSingleRunner or an
// AsyncBatchRunner.  SDKs will encounter an error if the AsyncRunner
// does not satisfy one of these interfaces.
type AsyncRunner interface {
	// anyRunner() is a non-exported method with no functional use
	// other than to make this a non-empty interface.
	anyRunner()
}

// AsyncSingleRunner is an interface implemented by single-observer
// callbacks.
type AsyncSingleRunner interface {
	// Run accepts a single instrument and function for capturing
	// observations of that instrument.  Each call to the function
	// receives one captured observation.  (The function accepts
	// multiple observations so the same implementation can be
	// used for batch runners.)
	Run(single AsyncImpl, capture func([]kv.KeyValue, ...Observation))

	AsyncRunner
}

// AsyncBatchRunner is an interface implemented by batch-observer
// callbacks.
type AsyncBatchRunner interface {
	// Run accepts a function for capturing observations of
	// multiple instruments.
	Run(capture func([]kv.KeyValue, ...Observation))

	AsyncRunner
}

// Observe captures a single integer value from the associated
// instrument callback, with the given labels.
func (ir Int64ObserverResult) Observe(value int64, labels ...kv.KeyValue) {
	ir.function(labels, Observation{
		instrument: ir.instrument,
		number:     NewInt64Number(value),
	})
}

// Observe captures a single floating point value from the associated
// instrument callback, with the given labels.
func (fr Float64ObserverResult) Observe(value float64, labels ...kv.KeyValue) {
	fr.function(labels, Observation{
		instrument: fr.instrument,
		number:     NewFloat64Number(value),
	})
}

// Observe captures a multiple observations from the associated batch
// instrument callback, with the given labels.
func (br BatchObserverResult) Observe(labels []kv.KeyValue, obs ...Observation) {
	br.function(labels, obs...)
}

// Observation is used for reporting a batch of metric
// values. Instances of this type should be created by Observer
// instruments (e.g., Int64Observer.Observation()).
type Observation struct {
	// number needs to be aligned for 64-bit atomic operations.
	number     Number
	instrument AsyncImpl
}

// AsyncImpl returns the instrument that created this observation.
// This returns an implementation-level object for use by the SDK,
// users should not refer to this.
func (m Observation) AsyncImpl() AsyncImpl {
	return m.instrument
}

// Number returns a number recorded in this observation.
func (m Observation) Number() Number {
	return m.number
}

// RegisterInt64Observer creates a new integer Observer instrument
// with the given name, running in a batch callback, and customized with
// options.  May return an error if the name is invalid (e.g., empty)
// or improperly registered (e.g., duplicate registration).
func (b BatchObserver) RegisterInt64Observer(name string, opts ...Option) (Int64Observer, error) {
	if b.runner == nil {
		return wrapInt64ObserverInstrument(NoopAsync{}, nil)
	}
	return wrapInt64ObserverInstrument(
		b.meter.newAsync(name, ObserverKind, Int64NumberKind, opts, b.runner))
}

// RegisterFloat64Observer creates a new floating point Observer with
// the given name, running in a batch callback, and customized with
// options.  May return an error if the name is invalid (e.g., empty)
// or improperly registered (e.g., duplicate registration).
func (b BatchObserver) RegisterFloat64Observer(name string, opts ...Option) (Float64Observer, error) {
	if b.runner == nil {
		return wrapFloat64ObserverInstrument(NoopAsync{}, nil)
	}
	return wrapFloat64ObserverInstrument(
		b.meter.newAsync(name, ObserverKind, Float64NumberKind, opts,
			b.runner))
}

// Observation returns an Observation, a BatchObserverCallback
// argument, for an asynchronous integer instrument.
// This returns an implementation-level object for use by the SDK,
// users should not refer to this.
func (i Int64Observer) Observation(v int64) Observation {
	return Observation{
		number:     NewInt64Number(v),
		instrument: i.instrument,
	}
}

// Observation returns an Observation, a BatchObserverCallback
// argument, for an asynchronous integer instrument.
// This returns an implementation-level object for use by the SDK,
// users should not refer to this.
func (f Float64Observer) Observation(v float64) Observation {
	return Observation{
		number:     NewFloat64Number(v),
		instrument: f.instrument,
	}
}

var _ AsyncSingleRunner = (*Int64ObserverCallback)(nil)
var _ AsyncSingleRunner = (*Float64ObserverCallback)(nil)
var _ AsyncBatchRunner = (*BatchObserverCallback)(nil)

// newInt64AsyncRunner returns a single-observer callback for integer Observer instruments.
func newInt64AsyncRunner(c Int64ObserverCallback) AsyncSingleRunner {
	return &c
}

// newFloat64AsyncRunner returns a single-observer callback for floating point Observer instruments.
func newFloat64AsyncRunner(c Float64ObserverCallback) AsyncSingleRunner {
	return &c
}

// newBatchAsyncRunner returns a batch-observer callback use with multiple Observer instruments.
func newBatchAsyncRunner(c BatchObserverCallback) AsyncBatchRunner {
	return &c
}

// anyRunner implements AsyncRunner.
func (*Int64ObserverCallback) anyRunner() {}

// anyRunner implements AsyncRunner.
func (*Float64ObserverCallback) anyRunner() {}

// anyRunner implements AsyncRunner.
func (*BatchObserverCallback) anyRunner() {}

// Run implements AsyncSingleRunner.
func (i *Int64ObserverCallback) Run(impl AsyncImpl, function func([]kv.KeyValue, ...Observation)) {
	(*i)(Int64ObserverResult{
		instrument: impl,
		function:   function,
	})
}

// Run implements AsyncSingleRunner.
func (f *Float64ObserverCallback) Run(impl AsyncImpl, function func([]kv.KeyValue, ...Observation)) {
	(*f)(Float64ObserverResult{
		instrument: impl,
		function:   function,
	})
}

// Run implements AsyncBatchRunner.
func (b *BatchObserverCallback) Run(function func([]kv.KeyValue, ...Observation)) {
	(*b)(BatchObserverResult{
		function: function,
	})
}
