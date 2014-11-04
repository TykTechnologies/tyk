package main

import (
	"html/template"
	"net/http"
	"strings"
	"net/url"
	"bytes"
	"crypto/md5"
	"io"
)

type WebHookRequestMethod string
const (
	WH_GET WebHookRequestMethod = "GET"
	WH_PUT WebHookRequestMethod = "PUT"
	WH_POST WebHookRequestMethod = "POST"
	WH_DELETE WebHookRequestMethod = "DELETE"
	WH_PATCH WebHookRequestMethod = "PATCH"
)

type WebHookHandlerConf struct {
	Method string
	TargetPath string
	TemplatePath string
	HeaderList map[string]string
	EventTimeout int64
}

// WebHookHandler is an event handler that triggers web hooks
type WebHookHandler struct {
	conf WebHookHandlerConf
	template *template.Template
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

	// Pre-load template on init
	webHookTemplate, tErr := template.ParseFiles(thisHandler.conf.TemplatePath)
	if tErr != nil {
		log.Error("Failed to load webhook template!: ", tErr)
		webHookTemplate = template.New("Default Tyk Webhook Template\n\n Type: {.EventType}\n Message: {.EventMetaDefault.Message}\n")
	}
	thisHandler.template = webHookTemplate

	if !w.checkURL(w.conf.TargetPath) {
		log.Error("Init failed for this webhook, invalid URL, URL must be absolute")
	}


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

func (w WebHookHandler) getRequestMethod(m string) WebHookRequestMethod {
	switch strings.ToUpper(m) {
		case "GET": return WH_GET
		case "PUT": return WH_PUT
		case "POST": return WH_POST
		case "DELETE": return WH_DELETE
		case "PATCH": return WH_DELETE
		default: log.Warning("Method must be one of GET, PUT, POST, DELETE or PATCH, defaulting to GET"); return WH_GET
	}
}

func (w WebHookHandler) checkURL(r string) bool {
	_, urlErr := url.ParseRequestURI(r)
	if urlErr != nil {
		log.Error("Failed to parse URL! ", urlErr)
		return false
	}
	return true
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (w WebHookHandler) HandleEvent(em EventMessage) {

	// Inject event message into template, render to string
	var reqBody bytes.Buffer
	w.template.Execute(&reqBody, em)

	// Construct request (method, body, params)
	req, reqErr := http.NewRequest(string(w.getRequestMethod(w.conf.Method)), w.conf.TargetPath, &reqBody)
	if reqErr != nil {
		log.Error("Failed to create request object: ", reqErr)
	}

	for key, val := range (w.conf.HeaderList) {
		req.Header.Add(key, val)
	}

	// Generate signature for request
	var rawRequest bytes.Buffer
	req.Write(&rawRequest)
	h := md5.New()
	io.WriteString(h, rawRequest.String())
	reqChecksum := string(h.Sum(nil))

	// Check request velocity for this hook (wasHookFired())
	if !w.wasHookFired(reqChecksum) {
		// Fire web hook as go routine (setHookFired())
		go w.doRequest(req)
		w.setHookFired(reqChecksum)
	}
}

func (w WebHookHandler) doRequest(req *http.Request) {
	client := &http.Client{}
	_, doReqErr := client.Do(req)
	if doReqErr != nil {
		log.Error("Webhook request failed: ", doReqErr)
	}
}
