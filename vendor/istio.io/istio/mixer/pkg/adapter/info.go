// Copyright 2017 Istio Authors.
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

package adapter

import (
	"github.com/gogo/protobuf/proto"
)

// Info describes the Adapter and provides a function to a Handler Builder method.
type Info struct {
	// Name returns the official name of the adapter, it must be RFC 1035 compatible DNS label.
	// Regex: "^[a-z]([-a-z0-9]*[a-z0-9])?$"
	// Name is used in Istio configuration, therefore it should be descriptive but short.
	// example: denier
	// Vendor adapters should use a vendor prefix.
	// example: mycompany-denier
	Name string
	// Impl is the package implementing the adapter.
	// example: "istio.io/istio/mixer/adapter/denier"
	Impl string
	// Description returns a user-friendly description of the adapter.
	Description string
	// NewBuilder is a function that creates a Builder which implements Builders associated
	// with the SupportedTemplates.
	NewBuilder NewBuilderFn
	// SupportedTemplates expresses all the templates the Adapter wants to serve.
	SupportedTemplates []string
	// DefaultConfig is a default configuration struct for this
	// adapter. This will be used by the configuration system to establish
	// the shape of the block of configuration state passed to the HandlerBuilder.Build method.
	DefaultConfig proto.Message
}

// NewBuilderFn is a function that creates a Builder.
type NewBuilderFn func() HandlerBuilder

// InfoFn returns an AdapterInfo object that Mixer will use to create HandlerBuilder
type InfoFn func() Info
