package interfaces

// Notifier Publisher interface in Event-Bus pattern
type Notifier interface {
	Notify(notif interface{}) bool
}
