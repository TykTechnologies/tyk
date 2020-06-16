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

//go:generate stringer -type=Kind

package metric

import (
	"context"

	"go.opentelemetry.io/otel/api/kv"
	"go.opentelemetry.io/otel/api/unit"
)

// Provider supports named Meter instances.
type Provider interface {
	// Meter gets a named Meter interface.  If the name is an
	// empty string, the provider uses a default name.
	Meter(name string) Meter
}

// Config contains some options for metrics of any kind.
type Config struct {
	// Description is an optional field describing the metric
	// instrument.
	Description string
	// Unit is an optional field describing the metric instrument.
	Unit unit.Unit
	// LibraryName is the name given to the Meter that created
	// this instrument.  See `Provider`.
	LibraryName string
}

// Option is an interface for applying metric options.
type Option interface {
	// Apply is used to set the Option value of a Config.
	Apply(*Config)
}

// Measurement is used for reporting a batch of metric
// values. Instances of this type should be created by instruments
// (e.g., Int64Counter.Measurement()).
type Measurement struct {
	// number needs to be aligned for 64-bit atomic operations.
	number     Number
	instrument SyncImpl
}

// SyncImpl returns the instrument that created this measurement.
// This returns an implementation-level object for use by the SDK,
// users should not refer to this.
func (m Measurement) SyncImpl() SyncImpl {
	return m.instrument
}

// Number returns a number recorded in this measurement.
func (m Measurement) Number() Number {
	return m.number
}

// Kind describes the kind of instrument.
type Kind int8

const (
	// MeasureKind indicates a Measure instrument.
	MeasureKind Kind = iota
	// ObserverKind indicates an Observer instrument.
	ObserverKind
	// CounterKind indicates a Counter instrument.
	CounterKind
)

// Descriptor contains all the settings that describe an instrument,
// including its name, metric kind, number kind, and the configurable
// options.
type Descriptor struct {
	name       string
	kind       Kind
	numberKind NumberKind
	config     Config
}

// NewDescriptor returns a Descriptor with the given contents.
func NewDescriptor(name string, mkind Kind, nkind NumberKind, opts ...Option) Descriptor {
	return Descriptor{
		name:       name,
		kind:       mkind,
		numberKind: nkind,
		config:     Configure(opts),
	}
}

// Name returns the metric instrument's name.
func (d Descriptor) Name() string {
	return d.name
}

// MetricKind returns the specific kind of instrument.
func (d Descriptor) MetricKind() Kind {
	return d.kind
}

// Description provides a human-readable description of the metric
// instrument.
func (d Descriptor) Description() string {
	return d.config.Description
}

// Unit describes the units of the metric instrument.  Unitless
// metrics return the empty string.
func (d Descriptor) Unit() unit.Unit {
	return d.config.Unit
}

// NumberKind returns whether this instrument is declared over int64,
// float64, or uint64 values.
func (d Descriptor) NumberKind() NumberKind {
	return d.numberKind
}

// LibraryName returns the metric instrument's library name, typically
// given via a call to Provider.Meter().
func (d Descriptor) LibraryName() string {
	return d.config.LibraryName
}

// Meter is the OpenTelemetry metric API, based on a `MeterImpl`
// implementation and the `Meter` library name.
//
// An uninitialized Meter is a no-op implementation.
type Meter struct {
	impl        MeterImpl
	libraryName string
}

// RecordBatch atomically records a batch of measurements.
func (m Meter) RecordBatch(ctx context.Context, ls []kv.KeyValue, ms ...Measurement) {
	if m.impl == nil {
		return
	}
	m.impl.RecordBatch(ctx, ls, ms...)
}

// NewInt64Counter creates a new integer Counter instrument with the
// given name, customized with options.  May return an error if the
// name is invalid (e.g., empty) or improperly registered (e.g.,
// duplicate registration).
func (m Meter) NewInt64Counter(name string, options ...Option) (Int64Counter, error) {
	return wrapInt64CounterInstrument(
		m.newSync(name, CounterKind, Int64NumberKind, options))
}

// NewFloat64Counter creates a new floating point Counter with the
// given name, customized with options.  May return an error if the
// name is invalid (e.g., empty) or improperly registered (e.g.,
// duplicate registration).
func (m Meter) NewFloat64Counter(name string, options ...Option) (Float64Counter, error) {
	return wrapFloat64CounterInstrument(
		m.newSync(name, CounterKind, Float64NumberKind, options))
}

// NewInt64Measure creates a new integer Measure instrument with the
// given name, customized with options.  May return an error if the
// name is invalid (e.g., empty) or improperly registered (e.g.,
// duplicate registration).
func (m Meter) NewInt64Measure(name string, opts ...Option) (Int64Measure, error) {
	return wrapInt64MeasureInstrument(
		m.newSync(name, MeasureKind, Int64NumberKind, opts))
}

// NewFloat64Measure creates a new floating point Measure with the
// given name, customized with options.  May return an error if the
// name is invalid (e.g., empty) or improperly registered (e.g.,
// duplicate registration).
func (m Meter) NewFloat64Measure(name string, opts ...Option) (Float64Measure, error) {
	return wrapFloat64MeasureInstrument(
		m.newSync(name, MeasureKind, Float64NumberKind, opts))
}

// RegisterInt64Observer creates a new integer Observer instrument
// with the given name, running a given callback, and customized with
// options.  May return an error if the name is invalid (e.g., empty)
// or improperly registered (e.g., duplicate registration).
func (m Meter) RegisterInt64Observer(name string, callback Int64ObserverCallback, opts ...Option) (Int64Observer, error) {
	if callback == nil {
		return wrapInt64ObserverInstrument(NoopAsync{}, nil)
	}
	return wrapInt64ObserverInstrument(
		m.newAsync(name, ObserverKind, Int64NumberKind, opts,
			newInt64AsyncRunner(callback)))
}

// RegisterFloat64Observer creates a new floating point Observer with
// the given name, running a given callback, and customized with
// options.  May return an error if the name is invalid (e.g., empty)
// or improperly registered (e.g., duplicate registration).
func (m Meter) RegisterFloat64Observer(name string, callback Float64ObserverCallback, opts ...Option) (Float64Observer, error) {
	if callback == nil {
		return wrapFloat64ObserverInstrument(NoopAsync{}, nil)
	}
	return wrapFloat64ObserverInstrument(
		m.newAsync(name, ObserverKind, Float64NumberKind, opts,
			newFloat64AsyncRunner(callback)))
}

// NewBatchObserver creates a new BatchObserver that supports
// making batches of observations for multiple instruments.
func (m Meter) NewBatchObserver(callback BatchObserverCallback) BatchObserver {
	return BatchObserver{
		meter:  m,
		runner: newBatchAsyncRunner(callback),
	}
}

// WithDescription applies provided description.
func WithDescription(desc string) Option {
	return descriptionOption(desc)
}

type descriptionOption string

func (d descriptionOption) Apply(config *Config) {
	config.Description = string(d)
}

// WithUnit applies provided unit.
func WithUnit(unit unit.Unit) Option {
	return unitOption(unit)
}

type unitOption unit.Unit

func (u unitOption) Apply(config *Config) {
	config.Unit = unit.Unit(u)
}

// WithLibraryName applies provided library name.  This is meant for
// use in `Provider` implementations that have not used
// `WrapMeterImpl`.  Implementations built using `WrapMeterImpl` have
// instrument descriptors taken care of through this package.
//
// This option will have no effect when supplied by the user.
// Provider implementations are expected to append this option after
// the user-supplied options when building instrument descriptors.
func WithLibraryName(name string) Option {
	return libraryNameOption(name)
}

type libraryNameOption string

func (r libraryNameOption) Apply(config *Config) {
	config.LibraryName = string(r)
}
