package main

import (
	"html/template"
	"net/http"
	"strings"
	"net/url"
	"bytes"
	"crypto/md5"
	"io"
	"io/ioutil"
	"encoding/hex"
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
		log.Error("Failed to load webhook template! Using defult. Error was: ", tErr)
		webHookTemplate, _ = template.ParseFiles("templates/default_webhook.json")
	}
	thisHandler.template = webHookTemplate

	if !thisHandler.checkURL(thisHandler.conf.TargetPath) {
		log.Error("Init failed for this webhook, invalid URL, URL must be absolute")
	}


	return thisHandler
}

// hookFired checks if an event has been fired within the EventTimeout setting
func (w WebHookHandler) WasHookFired(checksum string) bool {
	_, keyErr := w.store.GetKey(checksum)
	if keyErr != nil {
		// Key not found, so hook is in limit
		log.Info("Event can fire, no duplicates found")
		return false
	}

	return true
}

// setHookFired will create an expiring key for the checksum of the event
func (w WebHookHandler) setHookFired(checksum string) {
	log.Warning("Setting Webhook Checksum: ", checksum)
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
	log.Debug("Checking URL: ", r)
	_, urlErr := url.ParseRequestURI(r)
	if urlErr != nil {
		log.Error("Failed to parse URL! ", urlErr, r)
		return false
	}
	return true
}

func (w WebHookHandler) GetChecksum(reqBody string) (string, error) {
	var rawRequest bytes.Buffer
	// We do this twice because fuck it.
	localRequest, _ := http.NewRequest(string(w.getRequestMethod(w.conf.Method)), w.conf.TargetPath, bytes.NewBuffer([]byte(reqBody)))

	localRequest.Write(&rawRequest)
	h := md5.New()
	io.WriteString(h, rawRequest.String())

	reqChecksum := hex.EncodeToString(h.Sum(nil))

	return reqChecksum, nil
}

func (w WebHookHandler) BuildRequest(reqBody string) (*http.Request, error) {
	req, reqErr := http.NewRequest(string(w.getRequestMethod(w.conf.Method)), w.conf.TargetPath, bytes.NewBuffer([]byte(reqBody)))
	if reqErr != nil {
		log.Error("Failed to create request object: ", reqErr)
		return nil, reqErr
	}

	for key, val := range (w.conf.HeaderList) {
		req.Header.Add(key, val)
	}

	return req, nil
}

func (w WebHookHandler) CreateBody(em EventMessage) (string, error) {
	var reqBody bytes.Buffer
	w.template.Execute(&reqBody, em)

	return reqBody.String(), nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (w WebHookHandler) HandleEvent(em EventMessage) {

	// Inject event message into template, render to string
	reqBody, _ := w.CreateBody(em)

	// Construct request (method, body, params)
	req, reqErr := w.BuildRequest(reqBody)
	if reqErr != nil {
		return
	}

	// Generate signature for request

	//TODO: this breaks because we lose all our body data!
	reqChecksum, _ := w.GetChecksum(reqBody)

	// Check request velocity for this hook (wasHookFired())
	if !w.WasHookFired(reqChecksum) {
		// Fire web hook routine (setHookFired())

		client := &http.Client{}
		resp, doReqErr := client.Do(req)

		if doReqErr != nil {
			log.Error("Webhook request failed: ", doReqErr)
		} else {
			defer resp.Body.Close()
			content, readErr := ioutil.ReadAll(resp.Body)
			if readErr == nil {
				log.Warning(string(content))
			} else {
				log.Error(readErr)
			}
		}

		w.setHookFired(reqChecksum)
	}
}
