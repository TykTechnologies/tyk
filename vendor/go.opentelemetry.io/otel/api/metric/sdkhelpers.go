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

import (
	"context"

	"go.opentelemetry.io/otel/api/kv"
)

// MeterImpl is the interface an SDK must implement to supply a Meter
// implementation.
type MeterImpl interface {
	// RecordBatch atomically records a batch of measurements.
	RecordBatch(context.Context, []kv.KeyValue, ...Measurement)

	// NewSyncInstrument returns a newly constructed
	// synchronous instrument implementation or an error, should
	// one occur.
	NewSyncInstrument(descriptor Descriptor) (SyncImpl, error)

	// NewAsyncInstrument returns a newly constructed
	// asynchronous instrument implementation or an error, should
	// one occur.
	NewAsyncInstrument(
		descriptor Descriptor,
		runner AsyncRunner,
	) (AsyncImpl, error)
}

// InstrumentImpl is a common interface for synchronous and
// asynchronous instruments.
type InstrumentImpl interface {
	// Implementation returns the underlying implementation of the
	// instrument, which allows the implementation to gain access
	// to its own representation especially from a `Measurement`.
	Implementation() interface{}

	// Descriptor returns a copy of the instrument's Descriptor.
	Descriptor() Descriptor
}

// SyncImpl is the implementation-level interface to a generic
// synchronous instrument (e.g., Measure and Counter instruments).
type SyncImpl interface {
	InstrumentImpl

	// Bind creates an implementation-level bound instrument,
	// binding a label set with this instrument implementation.
	Bind(labels []kv.KeyValue) BoundSyncImpl

	// RecordOne captures a single synchronous metric event.
	RecordOne(ctx context.Context, number Number, labels []kv.KeyValue)
}

// BoundSyncImpl is the implementation-level interface to a
// generic bound synchronous instrument
type BoundSyncImpl interface {

	// RecordOne captures a single synchronous metric event.
	RecordOne(ctx context.Context, number Number)

	// Unbind frees the resources associated with this bound instrument. It
	// does not affect the metric this bound instrument was created through.
	Unbind()
}

// AsyncImpl is an implementation-level interface to an
// asynchronous instrument (e.g., Observer instruments).
type AsyncImpl interface {
	InstrumentImpl
}

// Configure is a helper that applies all the options to a Config.
func Configure(opts []Option) Config {
	var config Config
	for _, o := range opts {
		o.Apply(&config)
	}
	return config
}

// WrapMeterImpl constructs a `Meter` implementation from a
// `MeterImpl` implementation.
func WrapMeterImpl(impl MeterImpl, libraryName string) Meter {
	return Meter{
		impl:        impl,
		libraryName: libraryName,
	}
}

// MeterImpl returns the underlying MeterImpl of this Meter.
func (m Meter) MeterImpl() MeterImpl {
	return m.impl
}

// newSync constructs one new synchronous instrument.
func (m Meter) newSync(name string, metricKind Kind, numberKind NumberKind, opts []Option) (SyncImpl, error) {
	if m.impl == nil {
		return NoopSync{}, nil
	}
	desc := NewDescriptor(name, metricKind, numberKind, opts...)
	desc.config.LibraryName = m.libraryName
	return m.impl.NewSyncInstrument(desc)
}

// wrapInt64CounterInstrument returns an `Int64Counter` from a
// `SyncImpl`.  An error will be generated if the
// `SyncImpl` is nil (in which case a No-op is substituted),
// otherwise the error passes through.
func wrapInt64CounterInstrument(syncInst SyncImpl, err error) (Int64Counter, error) {
	common, err := checkNewSync(syncInst, err)
	return Int64Counter{syncInstrument: common}, err
}

// wrapFloat64CounterInstrument returns an `Float64Counter` from a
// `SyncImpl`.  An error will be generated if the
// `SyncImpl` is nil (in which case a No-op is substituted),
// otherwise the error passes through.
func wrapFloat64CounterInstrument(syncInst SyncImpl, err error) (Float64Counter, error) {
	common, err := checkNewSync(syncInst, err)
	return Float64Counter{syncInstrument: common}, err
}

// wrapInt64MeasureInstrument returns an `Int64Measure` from a
// `SyncImpl`.  An error will be generated if the
// `SyncImpl` is nil (in which case a No-op is substituted),
// otherwise the error passes through.
func wrapInt64MeasureInstrument(syncInst SyncImpl, err error) (Int64Measure, error) {
	common, err := checkNewSync(syncInst, err)
	return Int64Measure{syncInstrument: common}, err
}

// wrapFloat64MeasureInstrument returns an `Float64Measure` from a
// `SyncImpl`.  An error will be generated if the
// `SyncImpl` is nil (in which case a No-op is substituted),
// otherwise the error passes through.
func wrapFloat64MeasureInstrument(syncInst SyncImpl, err error) (Float64Measure, error) {
	common, err := checkNewSync(syncInst, err)
	return Float64Measure{syncInstrument: common}, err
}

// newAsync constructs one new asynchronous instrument.
func (m Meter) newAsync(name string, mkind Kind, nkind NumberKind, opts []Option, runner AsyncRunner) (AsyncImpl, error) {
	if m.impl == nil {
		return NoopAsync{}, nil
	}
	desc := NewDescriptor(name, mkind, nkind, opts...)
	desc.config.LibraryName = m.libraryName
	return m.impl.NewAsyncInstrument(desc, runner)
}

// wrapInt64ObserverInstrument returns an `Int64Observer` from a
// `AsyncImpl`.  An error will be generated if the
// `AsyncImpl` is nil (in which case a No-op is substituted),
// otherwise the error passes through.
func wrapInt64ObserverInstrument(asyncInst AsyncImpl, err error) (Int64Observer, error) {
	common, err := checkNewAsync(asyncInst, err)
	return Int64Observer{asyncInstrument: common}, err
}

// wrapFloat64ObserverInstrument returns an `Float64Observer` from a
// `AsyncImpl`.  An error will be generated if the
// `AsyncImpl` is nil (in which case a No-op is substituted),
// otherwise the error passes through.
func wrapFloat64ObserverInstrument(asyncInst AsyncImpl, err error) (Float64Observer, error) {
	common, err := checkNewAsync(asyncInst, err)
	return Float64Observer{asyncInstrument: common}, err
}
