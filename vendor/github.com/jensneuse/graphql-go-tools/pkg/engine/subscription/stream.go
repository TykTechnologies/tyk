package subscription

type Stream interface {
	Start(input []byte, next chan<- []byte, stop <-chan struct{})
	// UniqueIdentifier gives each stream a name, e.g. "kafka", "nats", "http-polling"
	// Don't give streams of the same type a different UID, e.g. don't use "kafka1", "kafka2"
	// This value should be static and the same for streams of the same kind
	UniqueIdentifier() []byte
}
