package gateway

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/headers"
)

func createGetHandler() *WebHookHandler {
	eventHandlerConf := config.WebHookHandlerConf{
		TargetPath:   TestHttpGet,
		Method:       "GET",
		EventTimeout: 10,
		TemplatePath: "../templates/default_webhook.json",
		HeaderList:   map[string]string{"x-tyk-test": "TEST"},
	}
	ev := &WebHookHandler{}
	if err := ev.Init(eventHandlerConf); err != nil {
		panic(err)
	}
	return ev
}

func TestNewValid(t *testing.T) {
	h := &WebHookHandler{}
	err := h.Init(map[string]interface{}{
		"method":        "POST",
		"target_path":   testHttpPost,
		"template_path": "../templates/default_webhook.json",
		"header_map":    map[string]string{"X-Tyk-Test-Header": "Tyk v1.BANANA"},
		"event_timeout": 10,
	})
	if err != nil {
		t.Error("Webhook Handler should have created valid configuration")
	}
}

func TestNewInvalid(t *testing.T) {
	h := &WebHookHandler{}
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
	rBody := `{
		"event": "QuotaExceeded",
		"message": "Key Quota Limit Exceeded",
		"path": "/about-lonelycoder/",
		"origin": "",
		"key": "4321",
		"timestamp": 2014-11-27 12:52:05.944549825 &#43;0000 GMT
	}`

	hook := createGetHandler()
	checksum, err := hook.Checksum(rBody)

	if err != nil {
		t.Error("Checksum should not have failed with good objet and body")
	}

	if checksum != "62a6b4fa9b45cd372b871764296fb3a5" {
		t.Error("Checksum is incorrect")
		t.Error(checksum)
	}
}

func TestBuildRequest(t *testing.T) {
	hook := createGetHandler()

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

	if got := req.Header.Get(headers.UserAgent); got != headers.TykHookshot {
		t.Error("Header User Agent is not correct!")
	}

	if got := req.Header.Get(headers.ContentType); got != headers.ApplicationJSON {
		t.Error("Header Content-Type is not correct!")
	}
}

func TestBuildRequestIngoreCanonicalHeaderKey(t *testing.T) {
	c := config.Global()
	defer ResetTestConfig()
	c.IgnoreCanonicalMIMEHeaderKey = true
	config.SetGlobal(c)
	eventHandlerConf := config.WebHookHandlerConf{
		TargetPath:   TestHttpGet,
		Method:       "GET",
		EventTimeout: 10,
		TemplatePath: "../templates/default_webhook.json",
		HeaderList:   map[string]string{NonCanonicalHeaderKey: NonCanonicalHeaderKey},
	}

	ev := &WebHookHandler{}
	if err := ev.Init(eventHandlerConf); err != nil {
		t.Fatal(err)
	}
	req, err := ev.BuildRequest("")
	if err != nil {
		t.Fatal(err)
	}
	got := req.Header[NonCanonicalHeaderKey][0]
	if got != NonCanonicalHeaderKey {
		t.Errorf("expected %q got %q", NonCanonicalHeaderKey, got)
	}
}

func TestCreateBody(t *testing.T) {
	em := config.EventMessage{
		Type:      EventQuotaExceeded,
		TimeStamp: "0",
	}

	hook := createGetHandler()
	body, err := hook.CreateBody(em)
	if err != nil {
		t.Error("Create body failed with error! ", err)
	}

	expectedBody := `"event": "QuotaExceeded"`
	if !strings.Contains(body, expectedBody) {
		t.Error("Body incorrect, is: ", body)
	}
}

func TestGet(t *testing.T) {
	eventHandler := createGetHandler()

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

	checksum, _ := eventHandler.Checksum(body)
	eventHandler.HandleEvent(eventMessage)

	if wasFired := eventHandler.WasHookFired(checksum); !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}

}

func TestPost(t *testing.T) {
	eventHandlerConf := config.WebHookHandlerConf{
		TargetPath:   "`+testHttpPost+`",
		Method:       "POST",
		EventTimeout: 10,
		TemplatePath: "templates/default_webhook.json",
		HeaderList:   map[string]string{"x-tyk-test": "TEST POST"},
	}

	eventHandler := &WebHookHandler{}
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

	checksum, _ := eventHandler.Checksum(body)
	eventHandler.HandleEvent(eventMessage)

	if wasFired := eventHandler.WasHookFired(checksum); !wasFired {
		t.Error("Checksum should have matched, event did not fire!")
	}
}

func TestNewCustomTemplate(t *testing.T) {
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
				globalConf := config.Global()
				old := globalConf.TemplatePath
				globalConf.TemplatePath = "missing-dir"
				config.SetGlobal(globalConf)
				defer func() {
					globalConf.TemplatePath = old
					config.SetGlobal(globalConf)
				}()
			}
			h := &WebHookHandler{}
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
	globalConf := config.Global()
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

			hook := &WebHookHandler{}
			if err := hook.Init(conf); err != nil {
				t.Fatal("Webhook Init failed with err ", err)
			}

			req, err := hook.BuildRequest("")
			if err != nil {
				t.Fatal("Failed to build request with error ", err)
			}

			if req.Header.Get(headers.ContentType) != ts.ExpectedContentType {
				t.Fatalf("Expect Content-Type %s. Got %s", ts.ExpectedContentType, req.Header.Get("Content-Type"))
			}
		})
	}

}
