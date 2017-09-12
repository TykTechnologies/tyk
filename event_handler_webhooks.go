package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

type WebHookRequestMethod string

const (
	WH_GET    WebHookRequestMethod = "GET"
	WH_PUT    WebHookRequestMethod = "PUT"
	WH_POST   WebHookRequestMethod = "POST"
	WH_DELETE WebHookRequestMethod = "DELETE"
	WH_PATCH  WebHookRequestMethod = "PATCH"

	// Define the Event Handler name so we can register it
	EH_WebHook apidef.TykEventHandlerName = "eh_web_hook_handler"
)

// WebHookHandler is an event handler that triggers web hooks
type WebHookHandler struct {
	conf     config.WebHookHandlerConf
	template *template.Template // non-nil if Init is run without error
	store    StorageHandler
}

// createConfigObject by default tyk will provide a ma[string]interface{} type as a conf, converting it
// specifically here makes it easier to handle, only happens once, so not a massive issue, but not pretty
func (w *WebHookHandler) createConfigObject(handlerConf interface{}) (config.WebHookHandlerConf, error) {
	newConf := config.WebHookHandlerConf{}

	asJSON, _ := json.Marshal(handlerConf)
	if err := json.Unmarshal(asJSON, &newConf); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Format of webhook configuration is incorrect: ", err)
		return newConf, err
	}

	return newConf, nil
}

// Init enables the init of event handler instances when they are created on ApiSpec creation
func (w *WebHookHandler) Init(handlerConf interface{}) error {
	var err error
	w.conf, err = w.createConfigObject(handlerConf)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Problem getting configuration, skipping. ", err)
		return err
	}

	w.store = &RedisClusterStorageManager{KeyPrefix: "webhook.cache."}
	w.store.Connect()

	// Pre-load template on init
	if w.conf.TemplatePath != "" {
		w.template, err = template.ParseFiles(w.conf.TemplatePath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "webhooks",
				"target": w.conf.TargetPath,
			}).Warning("Custom template load failure, using default: ", err)
		}
	}

	// We use the default if TemplatePath was empty or if we failed
	// to load it.
	if w.template == nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
			"target": w.conf.TargetPath,
		}).Info("Loading default template.")
		defaultPath := filepath.Join(globalConf.TemplatePath, "default_webhook.json")
		w.template, err = template.ParseFiles(defaultPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "webhooks",
			}).Error("Could not load the default template: ", err)
			return err
		}
	}

	log.WithFields(logrus.Fields{
		"prefix": "webhooks",
	}).Debug("Timeout set to: ", w.conf.EventTimeout)

	if !w.checkURL(w.conf.TargetPath) {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Init failed for this webhook, invalid URL, URL must be absolute")
	}

	return nil
}

// hookFired checks if an event has been fired within the EventTimeout setting
func (w *WebHookHandler) WasHookFired(checksum string) bool {
	if _, err := w.store.GetKey(checksum); err != nil {
		// Key not found, so hook is in limit
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Debug("Event can fire, no duplicates found")
		return false
	}

	return true
}

// setHookFired will create an expiring key for the checksum of the event
func (w *WebHookHandler) setHookFired(checksum string) {
	log.WithFields(logrus.Fields{
		"prefix": "webhooks",
	}).Debug("Setting Webhook Checksum: ", checksum)
	w.store.SetKey(checksum, "1", w.conf.EventTimeout)
}

func (w *WebHookHandler) getRequestMethod(m string) WebHookRequestMethod {
	upper := WebHookRequestMethod(strings.ToUpper(m))
	switch upper {
	case WH_GET, WH_PUT, WH_POST, WH_DELETE, WH_PATCH:
		return upper
	default:
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Warning("Method must be one of GET, PUT, POST, DELETE or PATCH, defaulting to GET")
		return WH_GET
	}
}

func (w *WebHookHandler) checkURL(r string) bool {
	log.WithFields(logrus.Fields{
		"prefix": "webhooks",
	}).Debug("Checking URL: ", r)
	if _, err := url.ParseRequestURI(r); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Failed to parse URL! ", err, r)
		return false
	}
	return true
}

func (w *WebHookHandler) Checksum(reqBody string) (string, error) {
	// We do this twice because fuck it.
	localRequest, _ := http.NewRequest(string(w.getRequestMethod(w.conf.Method)), w.conf.TargetPath, strings.NewReader(reqBody))
	h := md5.New()
	localRequest.Write(h)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (w *WebHookHandler) BuildRequest(reqBody string) (*http.Request, error) {
	req, err := http.NewRequest(string(w.getRequestMethod(w.conf.Method)), w.conf.TargetPath, strings.NewReader(reqBody))
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Failed to create request object: ", err)
		return nil, err
	}

	req.Header.Set("User-Agent", "Tyk-Hookshot")

	for key, val := range w.conf.HeaderList {
		req.Header.Set(key, val)
	}

	return req, nil
}

func (w *WebHookHandler) CreateBody(em config.EventMessage) (string, error) {
	var reqBody bytes.Buffer
	w.template.Execute(&reqBody, em)

	return reqBody.String(), nil
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (w *WebHookHandler) HandleEvent(em config.EventMessage) {

	// Inject event message into template, render to string
	reqBody, _ := w.CreateBody(em)

	// Construct request (method, body, params)
	req, err := w.BuildRequest(reqBody)
	if err != nil {
		return
	}

	// Generate signature for request
	reqChecksum, _ := w.Checksum(reqBody)

	// Check request velocity for this hook (wasHookFired())
	if w.WasHookFired(reqChecksum) {
		return
	}
	// Fire web hook routine (setHookFired())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Webhook request failed: ", err)
	} else {
		defer resp.Body.Close()
		content, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			log.WithFields(logrus.Fields{
				"prefix": "webhooks",
			}).Debug(string(content))
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "webhooks",
			}).Error(err)
		}
	}

	w.setHookFired(reqChecksum)
}
