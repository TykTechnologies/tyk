package streams

import "github.com/TykTechnologies/tyk/apidef/oas"

type XTykStreaming struct {
	// Info contains the main metadata for the API definition.
	Info oas.Info `bson:"info" json:"info"` // required
	// Server contains the configurations related to the server.
	Server oas.Server `bson:"server" json:"server"` // required
	// Streams contains the configurations related to Tyk Streams
	Streams map[string]interface{} `bson:"streams" json:"streams"` // required
	// Middleware contains the configurations related to the Tyk middleware.
	Middleware *oas.Middleware `bson:"middleware,omitempty" json:"middleware,omitempty"`
}
