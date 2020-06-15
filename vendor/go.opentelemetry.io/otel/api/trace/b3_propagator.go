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

package trace

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/api/propagation"
)

const (
	B3SingleHeader       = "X-B3"
	B3DebugFlagHeader    = "X-B3-Flags"
	B3TraceIDHeader      = "X-B3-TraceId"
	B3SpanIDHeader       = "X-B3-SpanId"
	B3SampledHeader      = "X-B3-Sampled"
	B3ParentSpanIDHeader = "X-B3-ParentSpanId"
	b3TraceIDPadding     = "0000000000000000"
)

// B3 propagator serializes SpanContext to/from B3 Headers.
// This propagator supports both version of B3 headers,
//  1. Single Header :
//    X-B3: {TraceId}-{SpanId}-{SamplingState}-{ParentSpanId}
//  2. Multiple Headers:
//    X-B3-TraceId: {TraceId}
//    X-B3-ParentSpanId: {ParentSpanId}
//    X-B3-SpanId: {SpanId}
//    X-B3-Sampled: {SamplingState}
//    X-B3-Flags: {DebugFlag}
//
// If SingleHeader is set to true then X-B3 header is used to inject and extract. Otherwise,
// separate headers are used to inject and extract.
type B3 struct {
	SingleHeader bool
}

var _ propagation.HTTPPropagator = B3{}

func (b3 B3) Inject(ctx context.Context, supplier propagation.HTTPSupplier) {
	sc := SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return
	}
	if b3.SingleHeader {
		sampled := sc.TraceFlags & FlagsSampled
		supplier.Set(B3SingleHeader,
			fmt.Sprintf("%s-%s-%.1d", sc.TraceID, sc.SpanID, sampled))
	} else {
		supplier.Set(B3TraceIDHeader, sc.TraceID.String())
		supplier.Set(B3SpanIDHeader, sc.SpanID.String())

		var sampled string
		if sc.IsSampled() {
			sampled = "1"
		} else {
			sampled = "0"
		}
		supplier.Set(B3SampledHeader, sampled)
	}
}

// Extract retrieves B3 Headers from the supplier
func (b3 B3) Extract(ctx context.Context, supplier propagation.HTTPSupplier) context.Context {
	var sc SpanContext
	if b3.SingleHeader {
		sc = b3.extractSingleHeader(supplier)
	} else {
		sc = b3.extract(supplier)
	}
	if !sc.IsValid() {
		return ctx
	}
	return ContextWithRemoteSpanContext(ctx, sc)
}

func fixB3TID(in string) string {
	if len(in) == 16 {
		in = b3TraceIDPadding + in
	}
	return in
}

func (b3 B3) extract(supplier propagation.HTTPSupplier) SpanContext {
	tid, err := IDFromHex(fixB3TID(supplier.Get(B3TraceIDHeader)))
	if err != nil {
		return EmptySpanContext()
	}
	sid, err := SpanIDFromHex(supplier.Get(B3SpanIDHeader))
	if err != nil {
		return EmptySpanContext()
	}
	sampled, ok := b3.extractSampledState(supplier.Get(B3SampledHeader))
	if !ok {
		return EmptySpanContext()
	}

	debug, ok := b3.extracDebugFlag(supplier.Get(B3DebugFlagHeader))
	if !ok {
		return EmptySpanContext()
	}
	if debug == FlagsSampled {
		sampled = FlagsSampled
	}

	sc := SpanContext{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: sampled,
	}

	if !sc.IsValid() {
		return EmptySpanContext()
	}

	return sc
}

func (b3 B3) extractSingleHeader(supplier propagation.HTTPSupplier) SpanContext {
	h := supplier.Get(B3SingleHeader)
	if h == "" || h == "0" {
		return EmptySpanContext()
	}
	sc := SpanContext{}
	parts := strings.Split(h, "-")
	l := len(parts)
	if l > 4 {
		return EmptySpanContext()
	}

	if l < 2 {
		return EmptySpanContext()
	}

	var err error
	sc.TraceID, err = IDFromHex(fixB3TID(parts[0]))
	if err != nil {
		return EmptySpanContext()
	}

	sc.SpanID, err = SpanIDFromHex(parts[1])
	if err != nil {
		return EmptySpanContext()
	}

	if l > 2 {
		var ok bool
		sc.TraceFlags, ok = b3.extractSampledState(parts[2])
		if !ok {
			return EmptySpanContext()
		}
	}
	if l == 4 {
		_, err = SpanIDFromHex(parts[3])
		if err != nil {
			return EmptySpanContext()
		}
	}

	if !sc.IsValid() {
		return EmptySpanContext()
	}

	return sc
}

// extractSampledState parses the value of the X-B3-Sampled b3Header.
func (b3 B3) extractSampledState(sampled string) (flag byte, ok bool) {
	switch sampled {
	case "", "0":
		return 0, true
	case "1":
		return FlagsSampled, true
	case "true":
		if !b3.SingleHeader {
			return FlagsSampled, true
		}
	case "d":
		if b3.SingleHeader {
			return FlagsSampled, true
		}
	}
	return 0, false
}

// extracDebugFlag parses the value of the X-B3-Sampled b3Header.
func (b3 B3) extracDebugFlag(debug string) (flag byte, ok bool) {
	switch debug {
	case "", "0":
		return 0, true
	case "1":
		return FlagsSampled, true
	}
	return 0, false
}

func (b3 B3) GetAllKeys() []string {
	if b3.SingleHeader {
		return []string{B3SingleHeader}
	}
	return []string{B3TraceIDHeader, B3SpanIDHeader, B3SampledHeader}
}
