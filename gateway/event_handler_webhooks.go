package gateway

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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/storage"
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
	store    storage.Handler

	contentType      string
	dashboardService DashboardServiceSender
	Gw               *Gateway
}

// createConfigObject by default tyk will provide a map[string]interface{} type as a conf, converting it
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

	w.store = &storage.RedisCluster{KeyPrefix: "webhook.cache.", RedisController: w.Gw.RedisController}
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

		if strings.HasSuffix(w.conf.TemplatePath, ".json") {
			w.contentType = header.ApplicationJSON
		}
	}

	// We use the default if TemplatePath was empty or if we failed
	// to load it.
	if w.template == nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
			"target": w.conf.TargetPath,
		}).Info("Loading default template.")
		defaultPath := filepath.Join(w.Gw.GetConfig().TemplatePath, "default_webhook.json")
		w.template, err = template.ParseFiles(defaultPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "webhooks",
			}).Error("Could not load the default template: ", err)
			return err
		}
		w.contentType = header.ApplicationJSON
	}

	log.WithFields(logrus.Fields{
		"prefix": "webhooks",
	}).Debug("Timeout set to: ", w.conf.EventTimeout)

	if !w.checkURL(w.conf.TargetPath) {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Init failed for this webhook, invalid URL, URL must be absolute")
	}

	if w.Gw.GetConfig().UseDBAppConfigs {
		dashboardServiceInit(w.Gw)
		w.dashboardService = w.Gw.DashService
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
	err := w.store.SetKey(checksum, "1", w.conf.EventTimeout)
	if err != nil {
		log.WithError(err).Error("could not set key")
	}
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

	req.Header.Set(header.UserAgent, header.TykHookshot)

	ignoreCanonical := w.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
	for key, val := range w.conf.HeaderList {
		setCustomHeader(req.Header, key, val, ignoreCanonical)
	}

	if req.Header.Get(header.ContentType) == "" {
		req.Header.Set(header.ContentType, w.contentType)
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

	cli := &http.Client{Timeout: 30 * time.Second}

	resp, err := cli.Do(req)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Webhook request failed: ", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			content, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				log.WithFields(logrus.Fields{
					"prefix":       "webhooks",
					"responseCode": resp.StatusCode,
				}).Debug(string(content))
			} else {
				log.WithFields(logrus.Fields{
					"prefix": "webhooks",
				}).Error(err)
			}

		} else {
			log.WithFields(logrus.Fields{
				"prefix":       "webhooks",
				"responseCode": resp.StatusCode,
			}).Error("Request to webhook failed")
		}
	}

	if w.dashboardService != nil && em.Type == EventTriggerExceeded {
		w.dashboardService.NotifyDashboardOfEvent(em.Meta)
	}

	w.setHookFired(reqChecksum)
}
