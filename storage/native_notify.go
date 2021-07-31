package storage

var _ Notify = (*nativeNotify)(nil)

type nativeNotify struct{}

func (nativeNotify) Publish(channel, message string) error                               { return nil }
func (nativeNotify) StartPubSubHandler(channel string, callback func(interface{})) error { return nil }
