package oas

// XTykStreaming represents the structure for Tyk streaming configurations.
type XTykStreaming struct {
	// Streams contains the configurations related to Tyk Streams.
	Streams map[string]interface{} `bson:"streams" json:"streams"` // required
}
