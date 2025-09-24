package gateway

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/model"
)

func (ts *Test) createWebHookHandler(t *testing.T) *WebHookHandler {
	t.Helper()

	handler := &WebHookHandler{Gw: ts.Gw}
	err := handler.Init(config.WebHookHandlerConf{
		TargetPath:   TestHttpGet,
		Method:       "GET",
		EventTimeout: 10,
		HeaderList:   map[string]string{"x-tyk-test": "TEST"},
	})
	assert.NoError(t, err)

	return handler
}

func TestNewValid(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	conf := map[string]interface{}{
		"disabled":      false,
		"method":        "POST",
		"target_path":   testHttpPost,
		"template_path": "../templates/default_webhook.json",
		"header_map":    map[string]string{"X-Tyk-Test-Header": "Tyk v1.BANANA"},
		"event_timeout": 10,
	}

	t.Run("enabled", func(t *testing.T) {
		h := &WebHookHandler{Gw: ts.Gw}
		err := h.Init(conf)
		assert.NoError(t, err)
		assert.False(t, h.conf.Disabled)
	})

	t.Run("disabled", func(t *testing.T) {
		conf["disabled"] = true
		h := &WebHookHandler{Gw: ts.Gw}
		err := h.Init(conf)
		assert.ErrorIs(t, err, ErrEventHandlerDisabled)
		assert.True(t, h.conf.Disabled)
	})
}

func TestNewInvalid(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	h := &WebHookHandler{Gw: ts.Gw}
	err := h.Init(map[string]interface{}{
		"method":        123,
		"target_path":   testHttpPost,
		"template_path": "../templates/default_webhook.json",
		"header_map":    map[string]string{"X-Tyk-Test-Header": "Tyk v1.BANANA"},
		"event_timeout": 10,
	})
	if err == nil {
		t.Error("Webhook Handler should have failed")
	}
}

func TestChecksum(t *testing.T) {
	t.Run("default case", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)

		rBody := `{
		"event": "QuotaExceeded",
		"message": "Key Quota Limit Exceeded",
		"path": "/about-lonelycoder/",
		"origin": "",
		"key": "4321",
		"timestamp": 2014-11-27 12:52:05.944549825 &#43;0000 GMT
	}`

		hook := ts.createWebHookHandler(t)
		checksum, err := hook.Checksum(config.EventMessage{Type: EventQuotaExceeded}, rBody)

		if err != nil {
			t.Error("Checksum should not have failed with good objet and body")
		}

		if checksum != "62a6b4fa9b45cd372b871764296fb3a5" {
			t.Error("Checksum is incorrect")
			t.Error(checksum)
		}
	})

	t.Run("certificate events", func(t *testing.T) {
		t.Run("should produce the same checksum for EventCertificateExpiringSoon", func(t *testing.T) {
			ts := StartTest(nil)
			t.Cleanup(ts.Close)

			em := config.EventMessage{
				Type: EventCertificateExpiringSoon,
				Meta: certcheck.EventCertificateExpiringSoonMeta{
					EventMetaDefault: model.EventMetaDefault{},
					CertID:           "123abc",
					CertName:         "Cert Soon To Expire",
					ExpiresAt:        time.Now().Add(time.Hour * 24),
					DaysRemaining:    1,
					APIID:            "123abc",
				},
				TimeStamp: "now",
			}

			hook := ts.createWebHookHandler(t)
			firstChecksum, err := hook.Checksum(em, "dynamic 1")
			assert.NoError(t, err)

			secondChecksum, err := hook.Checksum(em, "dynamic 2")
			assert.NoError(t, err)
			assert.Equal(t, firstChecksum, secondChecksum)
		})

		t.Run("should produce the same checksum for EventCertificateExpired", func(t *testing.T) {
			ts := StartTest(nil)
			t.Cleanup(ts.Close)

			em := config.EventMessage{
				Type: EventCertificateExpired,
				Meta: certcheck.EventCertificateExpiredMeta{
					EventMetaDefault: model.EventMetaDefault{},
					CertID:           "123abc",
					CertName:         "Cert Expired",
					ExpiredAt:        time.Now().Add(time.Hour * -24),
					DaysSinceExpiry:  1,
					APIID:            "123abc",
				},
				TimeStamp: "now",
			}

			hook := ts.createWebHookHandler(t)
			firstChecksum, err := hook.Checksum(em, "dynamic 1")
			assert.NoError(t, err)

			secondChecksum, err := hook.Checksum(em, "dynamic 2")
			assert.NoError(t, err)
			assert.Equal(t, firstChecksum, secondChecksum)
		})

		t.Run("should produce different checksums for EventCertificateExpired and EventCertificateExpiringSoon", func(t *testing.T) {
			ts := StartTest(nil)
			t.Cleanup(ts.Close)

			certID := "123abc"
			certName := "Cert With Same Name"

			emSoonToExpire := config.EventMessage{
				Type: EventCertificateExpiringSoon,
				Meta: certcheck.EventCertificateExpiringSoonMeta{
					EventMetaDefault: model.EventMetaDefault{},
					CertID:           certID,
					CertName:         certName,
					ExpiresAt:        time.Now().Add(time.Hour * 24),
					DaysRemaining:    1,
				},
				TimeStamp: "now",
			}

			emExpired := config.EventMessage{
				Type: EventCertificateExpired,
				Meta: certcheck.EventCertificateExpiredMeta{
					EventMetaDefault: model.EventMetaDefault{},
					CertID:           certID,
					CertName:         certName,
					ExpiredAt:        time.Now().Add(time.Hour * -24),
					DaysSinceExpiry:  1,
				},
				TimeStamp: "now",
			}

			hook := ts.createWebHookHandler(t)
			soonToExpireChecksum, err := hook.Checksum(emSoonToExpire, "dynamic soon to expire")
			assert.NoError(t, err)

			expiredChecksum, err := hook.Checksum(emExpired, "dynamic expired")
			assert.NoError(t, err)
			assert.NotEqual(t, soonToExpireChecksum, expiredChecksum)
		})
	})
}

func TestBuildRequest(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	hook := ts.createWebHookHandler(t)

	rBody := `{
		"event": "QuotaExceeded",
		"message": "Key Quota Limit Exceeded",
		"path": "/about-lonelycoder/",
		"origin": "",
		"key": "4321",
		"timestamp": 2014-11-27 12:52:05.944549825 &#43;0000 GMT
	}`

	req, err := hook.BuildRequest(rBody)
	if err != nil {
		t.Error("Request should have built cleanly.")
	}
	if req.Method != http.MethodGet {
		t.Error("Method hould be GET")
	}

	if got := req.Header.Get(header.UserAgent); got != header.TykHookshot {
		t.Error("Header User Agent is not correct!")
	}

	if got := req.Header.Get(header.ContentType); got != header.ApplicationJSON {
		t.Error("Header Content-Type is not correct!")
	}
}

func TestBuildRequestIngoreCanonicalHeaderKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	c := ts.Gw.GetConfig()
	c.IgnoreCanonicalMIMEHeaderKey = true
	ts.Gw.SetConfig(c)
	eventHandlerConf := config.WebHookHandlerConf{
		TargetPath:   TestHttpGet,
		Method:       "GET",
		EventTimeout: 10,
		TemplatePath: "../templates/default_webhook.json",
		HeaderList:   map[string]string{NonCanonicalHeaderKey: NonCanonicalHeaderKey},
	}

	ev := &WebHookHandler{Gw: ts.Gw}
	if err := ev.Init(eventHandlerConf); err != nil {
		t.Fatal(err)
	}
	req, err := ev.BuildRequest("")
	assert.NoError(t, err)

	got := req.Header[NonCanonicalHeaderKey][0]
	if got != NonCanonicalHeaderKey {
		t.Errorf("expected %q got %q", NonCanonicalHeaderKey, got)
	}
}

func TestCreateBody(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	em := config.EventMessage{
		Type:      EventQuotaExceeded,
		TimeStamp: "0",
		Meta:      EventKeyFailureMeta{},
	}

	hook := ts.createWebHookHandler(t)
	body, err := hook.CreateBody(em)
	assert.NoError(t, err)

	expectedBody := `"event": "QuotaExceeded"`
	if !strings.Contains(body, expectedBody) {
		t.Errorf("Body incorrect, is: %q", body)
	}
}

func TestGet(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	eventHandler := ts.createWebHookHandler(t)

	eventMessage := config.EventMessage{
		Type: EventKeyExpired,
		Meta: EventKeyFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
			Path:             "/banana",
			Origin:           "tyk.io",
			Key:              "123456789",
		},
	}

	body, err := eventHandler.CreateBody(eventMessage)
	assert.NoError(t, err)

	checksum, _ := eventHandler.Checksum(config.EventMessage{Type: EventKeyExpired}, body)
	eventHandler.HandleEvent(eventMessage)

	if wasFired := eventHandler.WasHookFired(checksum); !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}

}

func TestPost(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	eventHandlerConf := config.WebHookHandlerConf{
		TargetPath:   "`+testHttpPost+`",
		Method:       "POST",
		EventTimeout: 10,
		TemplatePath: "templates/default_webhook.json",
		HeaderList:   map[string]string{"x-tyk-test": "TEST POST"},
	}

	eventHandler := &WebHookHandler{Gw: ts.Gw}
	if err := eventHandler.Init(eventHandlerConf); err != nil {
		t.Fatal(err)
	}

	eventMessage := config.EventMessage{
		Type: EventKeyExpired,
		Meta: EventKeyFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "THIS IS A TEST"},
			Path:             "/banana",
			Origin:           "tyk.io",
			Key:              "123456789",
		},
	}

	body, _ := eventHandler.CreateBody(eventMessage)

	checksum, _ := eventHandler.Checksum(config.EventMessage{Type: EventKeyExpired}, body)
	eventHandler.HandleEvent(eventMessage)

	if wasFired := eventHandler.WasHookFired(checksum); !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}
}

func TestTemplates(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	conf := map[string]interface{}{
		"disabled":      false,
		"method":        "POST",
		"target_path":   testHttpPost,
		"template_path": "../templates/default_webhook.json",
		"header_map":    nil,
		"event_timeout": 10,
	}

	webhookHandler := ts.createWebHookHandler(t)
	err := webhookHandler.Init(conf)
	require.NoError(t, err)

	t.Run("CertificateExpiringSoon", func(t *testing.T) {
		type ActualExpiringSoon struct {
			Event         string `json:"event"`
			Message       string `json:"message"`
			CertID        string `json:"cert_id"`
			CertName      string `json:"cert_name"`
			ExpiresAt     string `json:"expires_at"`
			DaysRemaining int    `json:"days_remaining"`
			APIID         string `json:"api_id"`
			Timestamp     string `json:"timestamp"`
		}

		meta := certcheck.EventCertificateExpiringSoonMeta{
			EventMetaDefault: model.EventMetaDefault{
				Message: "Certificate will expire in 1 day",
			},
			CertID:        "123abc",
			CertName:      "Cert Soon To Expire",
			ExpiresAt:     time.Now().Add(time.Hour * 24),
			DaysRemaining: 1,
			APIID:         "123abc",
		}

		eventMessage := config.EventMessage{
			Type: EventCertificateExpiringSoon,
			Meta: meta,
		}

		stringMessage, err := webhookHandler.CreateBody(eventMessage)
		assert.NoError(t, err)

		var actualExpiringSoon ActualExpiringSoon
		err = json.Unmarshal([]byte(stringMessage), &actualExpiringSoon)
		assert.NoError(t, err)

		assert.Equal(t, string(EventCertificateExpiringSoon), actualExpiringSoon.Event)
		assert.Equal(t, meta.EventMetaDefault.Message, actualExpiringSoon.Message)
		assert.Equal(t, meta.CertID, actualExpiringSoon.CertID)
		assert.Equal(t, meta.CertName, actualExpiringSoon.CertName)
		assert.NotEmpty(t, actualExpiringSoon.ExpiresAt)
		assert.Equal(t, 1, actualExpiringSoon.DaysRemaining)
		assert.Equal(t, meta.APIID, actualExpiringSoon.APIID)
	})

	t.Run("CertificateExpired", func(t *testing.T) {
		type ActualExpired struct {
			Event           string `json:"event"`
			Message         string `json:"message"`
			CertID          string `json:"cert_id"`
			CertName        string `json:"cert_name"`
			ExpiredAt       string `json:"expired_at"`
			DaysSinceExpiry int    `json:"days_since_expiry"`
			APIID           string `json:"api_id"`
			Timestamp       string `json:"timestamp"`
		}

		meta := certcheck.EventCertificateExpiredMeta{
			EventMetaDefault: model.EventMetaDefault{
				Message: "Certificate expired since 1 day",
			},
			CertID:          "123abc",
			CertName:        "Cert Expired",
			ExpiredAt:       time.Now().Add(time.Hour * -24),
			DaysSinceExpiry: 1,
			APIID:           "123abc",
		}

		eventMessage := config.EventMessage{
			Type: EventCertificateExpired,
			Meta: meta,
		}

		stringMessage, err := webhookHandler.CreateBody(eventMessage)
		assert.NoError(t, err)

		var actualExpiringSoon ActualExpired
		err = json.Unmarshal([]byte(stringMessage), &actualExpiringSoon)
		assert.NoError(t, err)

		assert.Equal(t, string(EventCertificateExpired), actualExpiringSoon.Event)
		assert.Equal(t, meta.EventMetaDefault.Message, actualExpiringSoon.Message)
		assert.Equal(t, meta.CertID, actualExpiringSoon.CertID)
		assert.Equal(t, meta.CertName, actualExpiringSoon.CertName)
		assert.NotEmpty(t, actualExpiringSoon.ExpiredAt)
		assert.Equal(t, 1, actualExpiringSoon.DaysSinceExpiry)
		assert.Equal(t, meta.APIID, actualExpiringSoon.APIID)
	})
}

func TestNewCustomTemplate(t *testing.T) {

	ts := StartTest(nil)
	defer ts.Close()

	tests := []struct {
		name           string
		missingDefault bool
		templatePath   string
		wantErr        bool
	}{
		{"UseDefault", false, "", false},
		{"FallbackToDefault", false, "missing_webhook.json", false},
		{"UseCustom", false, "templates/breaker_webhook.json", false},
		{"MissingDefault", true, "", true},
		{"MissingDefaultFallback", true, "missing_webhook.json", true},
		{"MissingDefaultNotNeeded", true, "../templates/breaker_webhook.json", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.missingDefault {
				globalConf := ts.Gw.GetConfig()
				old := globalConf.TemplatePath
				globalConf.TemplatePath = "missing-dir"
				ts.Gw.SetConfig(globalConf)
				defer func() {
					globalConf.TemplatePath = old
					ts.Gw.SetConfig(globalConf)
				}()
			}
			h := &WebHookHandler{Gw: ts.Gw}
			err := h.Init(map[string]interface{}{
				"target_path":   testHttpPost,
				"template_path": tc.templatePath,
			})
			if tc.wantErr && err == nil {
				t.Fatalf("wanted error, got nil")
			} else if !tc.wantErr && err != nil {
				t.Fatalf("didn't want error, got: %v", err)
			}
			if err == nil && h.template == nil {
				t.Fatalf("didn't get an error but template is nil")
			}
		})
	}
}

func TestWebhookContentTypeHeader(t *testing.T) {
	gw := StartTest(nil)
	defer gw.Close()

	globalConf := gw.Gw.GetConfig()
	templatePath := globalConf.TemplatePath

	tests := []struct {
		Name                string
		TemplatePath        string
		InputHeaders        map[string]string
		ExpectedContentType string
	}{
		{"MissingTemplatePath", "", nil, "application/json"},
		{"MissingTemplatePath/CustomHeaders", "", map[string]string{"Content-Type": "application/xml"}, "application/xml"},
		{"InvalidTemplatePath", "randomPath", nil, "application/json"},
		{"InvalidTemplatePath/CustomHeaders", "randomPath", map[string]string{"Content-Type": "application/xml"}, "application/xml"},
		{"CustomTemplate", filepath.Join(templatePath, "transform_test.tmpl"), nil, ""},
		{"CustomTemplate/CustomHeaders", filepath.Join(templatePath, "breaker_webhook.json"), map[string]string{"Content-Type": "application/xml"}, "application/xml"},
	}

	for _, ts := range tests {
		t.Run(ts.Name, func(t *testing.T) {
			conf := config.WebHookHandlerConf{
				TemplatePath: ts.TemplatePath,
				HeaderList:   ts.InputHeaders,
			}

			hook := &WebHookHandler{Gw: gw.Gw}
			if err := hook.Init(conf); err != nil {
				t.Fatal("Webhook Init failed with err ", err)
			}

			req, err := hook.BuildRequest("")
			assert.NoError(t, err)

			if req.Header.Get(header.ContentType) != ts.ExpectedContentType {
				t.Fatalf("Expect Content-Type %s. Got %s", ts.ExpectedContentType, req.Header.Get("Content-Type"))
			}
		})
	}

}
