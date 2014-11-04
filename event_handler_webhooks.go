package main

type WebHookHandlerConf struct {
	Method string
	TargetPath string
	TemplatePath string
	parameterList map[string]string
	EventTimeout int64
}

// WebHookHandler is an event handler that triggers web hooks
type WebHookHandler struct {
	conf WebHookHandlerConf
	store *RedisStorageManager
}

// Not Pretty, but will avoi dmillions of connections
var WebHookRedisStorePointer *RedisStorageManager

// GetRedisInterfacePointer creates a reference to a redis connection pool that can be shared across all webhook instances
func GetRedisInterfacePointer() *RedisStorageManager {
	if WebHookRedisStorePointer == nil {
		WebHookRedisStorePointer = &RedisStorageManager{KeyPrefix: "webhook.cache."}
		WebHookRedisStorePointer.Connect()
	}

	return WebHookRedisStorePointer
}

// New enables the init of event handler instances when they are created on ApiSpec creation
func (w WebHookHandler) New(handlerConf interface{}) TykEventHandler {
	thisHandler := WebHookHandler{}
	thisHandler.conf = handlerConf.(WebHookHandlerConf)

	// Get a storage reference
	thisHandler.store = GetRedisInterfacePointer()

	// TODO: Pre-load templates on init

	return thisHandler
}

// hookFired checks if an event has been fired within the EventTimeout setting
func (w WebHookHandler) wasHookFired(checksum string) bool {
	_, keyErr := w.store.GetKey(checksum)
	if keyErr != nil {
		// Key not found, so hook is in limit
		return false
	}

	return true
}

// setHookFired will create an expiring key for the checksum of the event
func (w WebHookHandler) setHookFired(checksum string) {
	w.store.SetKey(checksum, "1", w.conf.EventTimeout)
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (l WebHookHandler) HandleEvent(em EventMessage) {

	// TODO: inject event message into template, render to string
	// TODO: Construct request (method, body, params)
	// TODO: Generate signature for request
	// TODO: Check RPM (wasHookFired())
	// TODO: Fire webhook as goroutine (setHookFired())


}

