package main

import (
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/config"
)

func createGetHandler() *WebHookHandler {
	eventHandlerConf := config.WebHookHandlerConf{
		TargetPath:   testHttpGet,
		Method:       "GET",
		EventTimeout: 10,
		TemplatePath: "templates/default_webhook.json",
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
		"template_path": "templates/default_webhook.json",
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
		"template_path": "templates/default_webhook.json",
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
	if req.Method != "GET" {
		t.Error("Method hould be GET")
	}

	if got := req.Header.Get("User-Agent"); got != "Tyk-Hookshot" {
		t.Error("Header User Agent is not correct!")
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
		{"MissingDefaultNotNeeded", true, "templates/breaker_webhook.json", false},
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
