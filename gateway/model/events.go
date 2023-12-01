package model

// EventMetaDefault is a standard embedded struct to be used with custom
// event metadata types, gives an interface for easily extending event
// metadata objects.
type EventMetaDefault struct {
	Message            string
	OriginatingRequest string
}

// EventKeyFailureMeta is the metadata structure for any failure related
// to a key, such as quota or auth failures.
type EventKeyFailureMeta struct {
	EventMetaDefault
	Path   string
	Origin string
	Key    string
}
