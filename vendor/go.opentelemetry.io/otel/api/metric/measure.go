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

// Float64Measure is a metric that records float64 values.
type Float64Measure struct {
	syncInstrument
}

// Int64Measure is a metric that records int64 values.
type Int64Measure struct {
	syncInstrument
}

// BoundFloat64Measure is a bound instrument for Float64Measure.
//
// It inherits the Unbind function from syncBoundInstrument.
type BoundFloat64Measure struct {
	syncBoundInstrument
}

// BoundInt64Measure is a bound instrument for Int64Measure.
//
// It inherits the Unbind function from syncBoundInstrument.
type BoundInt64Measure struct {
	syncBoundInstrument
}

// Bind creates a bound instrument for this measure. The labels are
// associated with values recorded via subsequent calls to Record.
func (c Float64Measure) Bind(labels ...kv.KeyValue) (h BoundFloat64Measure) {
	h.syncBoundInstrument = c.bind(labels)
	return
}

// Bind creates a bound instrument for this measure. The labels are
// associated with values recorded via subsequent calls to Record.
func (c Int64Measure) Bind(labels ...kv.KeyValue) (h BoundInt64Measure) {
	h.syncBoundInstrument = c.bind(labels)
	return
}

// Measurement creates a Measurement object to use with batch
// recording.
func (c Float64Measure) Measurement(value float64) Measurement {
	return c.float64Measurement(value)
}

// Measurement creates a Measurement object to use with batch
// recording.
func (c Int64Measure) Measurement(value int64) Measurement {
	return c.int64Measurement(value)
}

// Record adds a new value to the list of measure's records. The
// labels should contain the keys and values to be associated with
// this value.
func (c Float64Measure) Record(ctx context.Context, value float64, labels ...kv.KeyValue) {
	c.directRecord(ctx, NewFloat64Number(value), labels)
}

// Record adds a new value to the list of measure's records. The
// labels should contain the keys and values to be associated with
// this value.
func (c Int64Measure) Record(ctx context.Context, value int64, labels ...kv.KeyValue) {
	c.directRecord(ctx, NewInt64Number(value), labels)
}

// Record adds a new value to the list of measure's records using the labels
// previously bound to the measure via Bind()
func (b BoundFloat64Measure) Record(ctx context.Context, value float64) {
	b.directRecord(ctx, NewFloat64Number(value))
}

// Record adds a new value to the list of measure's records using the labels
// previously bound to the measure via Bind()
func (b BoundInt64Measure) Record(ctx context.Context, value int64) {
	b.directRecord(ctx, NewInt64Number(value))
}
