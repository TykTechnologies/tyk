package gateway

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	htmltemplate "html/template"
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
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/storage"
)

type WebHookRequestMethod string

const (
	WH_GET    WebHookRequestMethod = "GET"
	WH_PUT    WebHookRequestMethod = "PUT"
	WH_POST   WebHookRequestMethod = "POST"
	WH_DELETE WebHookRequestMethod = "DELETE"
	WH_PATCH  WebHookRequestMethod = "PATCH"
)

var (
	// ErrEventHandlerDisabled is returned when the event handler is disabled.
	ErrEventHandlerDisabled = errors.New("event handler disabled")

	// ErrCouldNotCastMetaData is returned when metadata cannot be cast to the expected type.
	ErrCouldNotCastMetaData = errors.New("could not cast meta data")
)

// WebHookHandler is an event handler that triggers web hooks
type WebHookHandler struct {
	conf     apidef.WebHookHandlerConf
	template *htmltemplate.Template // non-nil if Init is run without error
	store    storage.Handler

	contentType      string
	dashboardService DashboardServiceSender
	Gw               *Gateway
}

// Init enables the init of event handler instances when they are created on ApiSpec creation
func (w *WebHookHandler) Init(handlerConf interface{}) error {
	var err error
	if err = w.conf.Scan(handlerConf); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Problem getting configuration, skipping. ", err)
		return err
	}

	if w.conf.Disabled {
		log.WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Infof("skipping disabled webhook %s", w.conf.Name)
		return ErrEventHandlerDisabled
	}

	w.store = &storage.RedisCluster{KeyPrefix: "webhook.cache.", ConnectionHandler: w.Gw.StorageConnectionHandler}
	w.store.Connect()

	// Pre-load template on init
	if w.conf.TemplatePath != "" {
		w.template, err = htmltemplate.ParseFiles(w.conf.TemplatePath)
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
		w.template = htmltemplate.New("default_webhook.json").Funcs(htmltemplate.FuncMap{
			"as_rfc3339":             templateFuncAsRFC3339(),
			"as_rfc3339_from_string": templateFuncAsRFC3339FromString(log),
		})
		w.template, err = w.template.ParseFiles(defaultPath)
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
	if r == "" {
		return false
	}

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

func (w *WebHookHandler) Checksum(em config.EventMessage, reqBody string) (string, error) {
	h := md5.New()

	// EventCertificateExpiringSoon and EventCertificateExpired do have dynamic bodies.
	// Checksum will always be different, so a different strategy is needed in those cases.
	switch em.Type {
	case EventCertificateExpiringSoon:
		meta, ok := em.Meta.(certcheck.EventCertificateExpiringSoonMeta)
		if !ok {
			return "", ErrCouldNotCastMetaData
		}
		hashBody := fmt.Sprintf("%s%s%s%s%s",
			em.Type,
			meta.CertID,
			meta.CertName,
			meta.ExpiresAt.String(),
			meta.APIID,
		)
		h.Write([]byte(hashBody))
	case EventCertificateExpired:
		meta, ok := em.Meta.(certcheck.EventCertificateExpiredMeta)
		if !ok {
			return "", ErrCouldNotCastMetaData
		}
		hashBody := fmt.Sprintf("%s%s%s%s%s",
			em.Type,
			meta.CertID,
			meta.CertName,
			meta.ExpiredAt.String(),
			meta.APIID,
		)
		h.Write([]byte(hashBody))
	default:
		localRequest, err := http.NewRequest(string(w.getRequestMethod(w.conf.Method)), w.conf.TargetPath, strings.NewReader(reqBody))
		if err != nil {
			return "", err
		}
		err = localRequest.Write(h)
		if err != nil {
			return "", err
		}
	}

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

// CreateBody will render the webhook event message template and return it as a string.
// If an error occurs, an empty string will be returned alongside an error.
func (w *WebHookHandler) CreateBody(em config.EventMessage) (string, error) {
	var reqBody bytes.Buffer
	err := w.template.Execute(&reqBody, em)
	if err != nil {
		return "", err
	}
	return reqBody.String(), err
}

// HandleEvent will be fired when the event handler instance is found in an APISpec EventPaths object during a request chain
func (w *WebHookHandler) HandleEvent(em config.EventMessage) {

	// Inject event message into template, render to string
	reqBody, err := w.CreateBody(em)
	if err != nil {
		// We're just logging the template rendering issue here
		// but we're passing on the partial rendered contents
		log.WithError(err).WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Webhook template rendering error")
		return
	}

	// Construct request (method, body, params)
	req, err := w.BuildRequest(reqBody)
	if err != nil {
		return
	}

	// Generate signature for request
	reqChecksum, err := w.Checksum(em, reqBody)
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"prefix": "webhooks",
		}).Error("Webhook checksum error")
		return
	}

	// Check request velocity for this hook (wasHookFired())
	if w.WasHookFired(reqChecksum) {
		return
	}

	// Create HTTP client using factory for webhook service
	clientFactory := NewExternalHTTPClientFactory(w.Gw)
	cli, err := clientFactory.CreateWebhookClient()
	if err != nil {
		log.WithError(err).Error("Failed to create webhook HTTP client, falling back to default")
		log.Debug("[ExternalServices] Falling back to legacy webhook client due to factory error")
		cli = &http.Client{Timeout: 30 * time.Second}
	} else {
		log.Debugf("[ExternalServices] Using external services webhook client for URL: %s", req.URL.String())
	}

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

func templateFuncAsRFC3339() func(time.Time) string {
	return func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
}

func templateFuncAsRFC3339FromString(log *logrus.Logger) func(string) string {
	return func(s string) string {
		t, err := time.Parse("2006-01-02 15:04:05.999999 -0700 MST", s)
		if err == nil {
			return t.Format(time.RFC3339)
		}

		log.WithFields(logrus.Fields{
			"prefix":   "webhooks",
			"datetime": s,
			"error":    err.Error(),
		}).
			Debug("Could not parse time to RFC3339 from string.")

		// Fallback to the original string
		return s
	}
}
