package oas

import "github.com/TykTechnologies/tyk/apidef"

// XTykStreaming represents the structure for Tyk streaming configurations.
type XTykStreaming struct {
	// Info contains the main metadata for the API definition.
	Info Info `bson:"info" json:"info"` // required
	// Server contains the configurations related to the server.
	Server Server `bson:"server" json:"server"` // required
	// Streams contains the configurations related to Tyk Streams
	Streams map[string]interface{} `bson:"streams" json:"streams"` // required
	// Middleware contains the configurations related to the Tyk middleware.
	Middleware *Middleware `bson:"middleware,omitempty" json:"middleware,omitempty"`
}

func (x *XTykStreaming) Fill(api apidef.APIDefinition) {
	x.Info.Fill(api)
	x.Server.Fill(api)

	if x.Middleware == nil {
		x.Middleware = &Middleware{}
	}

	x.Middleware.Fill(api)
	if ShouldOmit(x.Middleware) {
		x.Middleware = nil
	}
}

func (x *XTykStreaming) ExtractTo(api *apidef.APIDefinition) {
	api.SetDisabledFlags()

	x.Info.ExtractTo(api)
	x.Server.ExtractTo(api)

	if x.Middleware == nil {
		x.Middleware = &Middleware{}
		defer func() {
			x.Middleware = nil
		}()
	}

	x.Middleware.ExtractTo(api)
}

// enableContextVariablesIfEmpty enables context variables in middleware.global.contextVariables.
// Context variables will be set only if it is not set, if it is already set to false, it won't be enabled.
func (x *XTykStreaming) enableContextVariablesIfEmpty() {
	if x.Middleware == nil {
		x.Middleware = &Middleware{}
	}

	if x.Middleware.Global == nil {
		x.Middleware.Global = &Global{}
	}

	if x.Middleware.Global.ContextVariables == nil {
		x.Middleware.Global.ContextVariables = &ContextVariables{
			Enabled: true,
		}
	}
}

// enableTrafficLogsIfEmpty enables traffic logs in middleware.global.trafficLogs.
// Traffic logs will be set only if it is not set. If it is already set to false, it won't be enabled.
func (x *XTykStreaming) enableTrafficLogsIfEmpty() {
	if x.Middleware == nil {
		x.Middleware = &Middleware{}
	}

	if x.Middleware.Global == nil {
		x.Middleware.Global = &Global{}
	}

	if x.Middleware.Global.TrafficLogs == nil {
		x.Middleware.Global.TrafficLogs = &TrafficLogs{
			Enabled: true,
		}
	}
}
